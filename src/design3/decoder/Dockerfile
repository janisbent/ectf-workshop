FROM alpine:3.21.2

LABEL version="0.1"

RUN apk add \
    bash=~5.2 \
    gcc-arm-none-eabi=~14.2 \
    binutils-arm-none-eabi=~2.42 \
    clang19-extra-tools=~19.1 \
    python3=~3.12 \
    py3-pip=~24.3 \
    python3-dev~=3.12 \
    bear=~3.1

# break-system-packages and root-user-action are safe because this is a container
RUN pip install \
    --disable-pip-version-check \
    --break-system-packages \
    --root-user-action ignore \
    loguru==0.7.3 \
    pymonocypher==4.0.2.5 \
    pyelftools==0.31

ENV IN_CONTAINER=1

WORKDIR /decoder

# Default invocation, for compat with eCTF build tools
CMD ["bash", "-c", "./build.sh build && cp build/max78000.elf build/max78000.bin /out"]
