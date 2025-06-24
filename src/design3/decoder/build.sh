#!/bin/bash

# Derived from MSDK's labyrinth of makefiles, Apache-2 license

set -e
shopt -s nullglob
cd "$(dirname "${BASH_SOURCE[0]}")"

##############################
# Target and toolchain setup #
##############################

BUILD_DIR=build
PROJECT=max78000 # filename needed by ectf build system

# Target platform
TARGET=MAX78000
TARGET_REV=0x4131
BOARD=FTHR_RevA

# Tools
PREFIX=arm-none-eabi
CC=${PREFIX}-gcc
AS=$CC # to allow using preprocessor
LD=$CC
OBJCOPY=${PREFIX}-objcopy
FORMAT=clang-format

# Misc configuration
DOCKER_IMAGE=build-decoder
GLOBAL_SECRETS=/global.secrets
SECRETS_C="$BUILD_DIR"/secrets.c

##########################
# Enter docker container #
##########################

if [[ -z $IN_CONTAINER ]]; then
    echo 'entering docker container'

    mkdir -p "$BUILD_DIR"

    cd .. # at root of code repo
    if docker run \
              --rm \
              -v ./decoder:/decoder \
              -v ./global.secrets:"$GLOBAL_SECRETS":ro \
              -e DECODER_ID="$DECODER_ID" \
              -e IN_CONTAINER=1 \
              "$DOCKER_IMAGE" \
              bear \
                   --output "${BUILD_DIR}/compile_commands_tmp.json" \
                   -- \
                   ./build.sh "$@"
    then
        # Only save compile commands if we actually built anything
        case "$1" in
            build | all | '' )
                # Map paths from container to host paths
                sed -e "s#/decoder#${PWD}/decoder#g" \
                    decoder/${BUILD_DIR}/compile_commands_tmp.json \
                    > decoder/${BUILD_DIR}/compile_commands.json
            ;;
        esac
    fi

    exit
fi

# Everything below this point only runs inside our container

########################
# Source/include paths #
########################

# Our code
PROJ_SRCPATH+=(src)
PROJ_INCPATH+=(inc)

SRCPATH+=("${PROJ_SRCPATH[@]}")
INCPATH+=("${PROJ_INCPATH[@]}")

# Libraries
SRCPATH+=(lib/msdk-lib/ICC)
SRCPATH+=(lib/msdk-lib/UART)
SRCPATH+=(lib/msdk-lib/GPIO)
SRCPATH+=(lib/msdk-lib/SYS)
SRCPATH+=(lib/msdk-lib/FLC)
SRCPATH+=(lib/msdk-lib/TMR)
SRCPATH+=(lib/msdk-lib/TRNG)

INCPATH+=(lib/msdk-lib)
INCPATH+=(lib/msdk-lib/Include)
INCPATH+=(lib/msdk-lib/IncludeMAX78000)
INCPATH+=(lib/msdk-lib/PeriphDriversMAX78000/)

SRCPATH+=(lib/monocypher)
INCPATH+=(lib/monocypher)

# Resolve sources from paths
# Glob everything twice to appease the ghosts

# for build
_=(${SRCPATH[@]/%/\/*.c})
SRCS+=(${SRCPATH[@]/%/\/*.c})
_=(${SRCPATH[@]/%/\/*.S})
SRCS+=(${SRCPATH[@]/%/\/*.S})

# for formatting
_=(${PROJ_SRCPATH[@]/%/\/*.c})
PROJ_FILES+=(${PROJ_SRCPATH[@]/%/\/*.c})
_=(${PROJ_INCPATH[@]/%/\/*.h})
PROJ_FILES+=(${PROJ_INCPATH[@]/%/\/*.h})

# Auto-generated source files (add manually, since they are not found in the paths)
SRCS+=("$SECRETS_C")

##################
# Compiler flags #
##################

# Float settings
MFLOAT_ABI=softfp
MFPU=fpv4-sp-d16

DEFAULT_OPTIMIZE_FLAGS=(-ffunction-sections
                        -fdata-sections
                        -fsingle-precision-constant
                        -falign-functions=64
                        -O2)

DEFAULT_WARNING_FLAGS=(-Wall
                       -Wno-format
                       -Wdouble-promotion
                       -Werror)

AFLAGS=(-mthumb
        -mcpu=cortex-m4)

CFLAGS=(--std=c23
        -mthumb
        -mcpu=cortex-m4
        -mfloat-abi="$MFLOAT_ABI"
        -mfpu="$MFPU"
        '-Wa,-mimplicit-it=thumb'
        "${DEFAULT_OPTIMIZE_FLAGS[@]}"
        "${DEFAULT_WARNING_FLAGS[@]}"
        -c
        -fno-isolate-erroneous-paths-dereference
        -D__unused='[[gnu::unused]]'
        -DTARGET="$TARGET"
        -DTARGET_REV="$TARGET_REV"
        -falign-functions=64
        -falign-loops=64
        -ffreestanding)

LDFLAGS=(-mthumb
         -mcpu=cortex-m4
         -mfloat-abi="$MFLOAT_ABI"
         -mfpu="$MFPU"
         '-Wl,--gc-sections'
         "-Wl,-Map=${BUILD_DIR}/${PROJECT}.map"
         -nostartfiles
         -nostdlib
         -ffreestanding)

# Add the include file paths to AFLAGS and CFLAGS.
AFLAGS+=("${INCPATH[@]/#/-I}")
CFLAGS+=("${INCPATH[@]/#/-I}")
# LDFLAGS+=(${LIBPATH[@]/#/-L})

###########
# Actions #
###########

function clean {
    rm -rf "$BUILD_DIR"
}

function build {
    if [[ -z $DECODER_ID ]]; then
        echo 'environment var parameter DECODER_ID not specified'
        exit 1
    fi

    mkdir -p "$BUILD_DIR"

    # break-system-packages and root-user-action are safe because this is a container
    echo 'python setup...'
    pip install \
        --quiet \
        --disable-pip-version-check \
        --break-system-packages \
        --root-user-action ignore \
        --editable \
        ./ppp_common

    # Generate keys required by the decoder
    echo 'generate: secrets.c'
    python -m ppp_common.gen_secrets_c "$GLOBAL_SECRETS" "$SECRETS_C" "$DECODER_ID"

    # Build objects
    echo 'building...'
    OBJS=()
    for src_file in "${SRCS[@]}"; do
        # From https://stackoverflow.com/questions/965053/extract-filename-and-extension-in-bash
        src_name="$(basename "$src_file")"
        extn="${src_name##*.}"
        name="${src_name%.*}"

        obj_file="${BUILD_DIR}/${name}.o"

        case "$extn" in
            c )
                echo "c: $src_name"
                "$CC" "${CFLAGS[@]}" -o "$obj_file" "$src_file" -DDECODER_ID="$DECODER_ID"
            ;;
            S )
                echo "S: $src_name"
                "$AS" "${AFLAGS[@]}" -o "$obj_file" -c "$src_file"
            ;;
            * )
                echo "unknown file in source paths!: $src_file"
                exit 1
            ;;
        esac

        OBJS+=("$obj_file")
    done

    # generate linker script using :sparkles: Symbol Shimmy :sparkles:
    echo 'symbol shimmy: firmware.ld'
    python -m ppp_common.symbol_shimmy \
           --template firmware.ld.template \
           --secrets "$GLOBAL_SECRETS" \
           --id "$DECODER_ID" \
           "${OBJS[@]}" \
           > "${BUILD_DIR}/firmware.ld"

    # Link objects
    echo "link: ${PROJECT}.elf"
    "$LD" -T "${BUILD_DIR}/firmware.ld" "${LDFLAGS[@]}" -o "${BUILD_DIR}/${PROJECT}.elf" "${OBJS[@]}"

    # Generate a subscription for channel 0
    python -m ppp_common.gen_subscription --force --embeddable "$GLOBAL_SECRETS" "${BUILD_DIR}/channel0.bin" "$DECODER_ID" 0 0xFFFF_FFFF_FFFF_FFFF 0

    # Patch in channel 0's data
    "$OBJCOPY" --set-section-flags .channel0=contents,alloc,load,readonly --update-section ".channel0=${BUILD_DIR}/channel0.bin" "${BUILD_DIR}/${PROJECT}.elf" "${BUILD_DIR}/${PROJECT}.elf"

    # Convert to raw
    echo "copy: ${PROJECT}.bin"
    "$OBJCOPY"  "${BUILD_DIR}/${PROJECT}.elf" -Obinary "${BUILD_DIR}/${PROJECT}.bin"
}

function debug {
    cat <<EOF
IN_CONTAINER = $IN_CONTAINER
DECODER_ID = $DECODER_ID

CC = $CC
AS = $AS
LD = $LD
TARGET = $TARGET
BOARD = $BOARD
BUILD_DIR = $BUILD_DIR
PROJECT = $PROJECT

SRCPATH = ${SRCPATH[*]}

INCPATH = ${INCPATH[*]}

SRCS = ${SRCS[*]}

PROJ_FILES = ${PROJ_FILES[*]}

CFLAGS = ${CFLAGS[*]}

AFLAGS = ${AFLAGS[*]}

LDFLAGS = ${LDFLAGS[*]}

EOF
    # print resolved incpath
    echo | "$CC" "${CFLAGS[@]}" -E -Wp,-v -
}

function format {
    for file in "${PROJ_FILES[@]}"; do
        echo "format: $(basename "$file")"
        "$FORMAT" -i "$file"
    done
}

function check-format {
    "$FORMAT" --dry-run -Werror "${PROJ_FILES[@]}"
}

case "$1" in
    build | all | '' ) build        ;;
    clean            ) clean        ;;
    format           ) format       ;;
    check-format     ) check-format ;;
    debug            ) debug        ;;
    * )
        echo "unknown action $1"
        exit 1
    ;;
esac

exit
