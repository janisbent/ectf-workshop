if [[ $# -ne 1 ]]; then
    echo "ERROR: Must have one argument" >&2
    echo "Usage: $0 <design>" >&2
    return 1
fi
if [[ ! -e "src/$1" ]]; then
    echo "ERROR: Design '$1' doesn't exist" >&2
    return 2
fi
if [[ ! -e "target/$1" ]]; then
    echo "ERROR: Design '$1' hasn't been built! Use 'make $1' first" >&2
    return 2
fi

export NAME=$1
export SRC=$PWD/src/$1
export VENV=$SRC/.venv
export DECODER=$SRC/decoder

source $VENV/bin/activate
cd target/$1


alias gen_secrets="python -m ectf25_design.gen_secrets global.secrets 1 2 3 4"
function build_decoder {
    docker run --rm -v $DECODER/:/decoder -v ./global.secrets:/global.secrets -v ./$1.build:/out -e DECODER_ID=0x$1 $NAME-decoder
}
alias gen_subscription="python -m ectf25_design.gen_subscription global.secrets"
function flash {
    python -m ectf25.utils.flash $1/max78000.bin $2
}
function list {
    python -m ectf25.tv.list $1
}
function subscribe {
    python -m ectf25.tv.subscribe $1 $2
}
function run {
    python -m ectf25.utils.tester --secrets global.secrets --port $1 --delay 0.1 rand --channels $2
}