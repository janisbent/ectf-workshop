if [[ $# -ne 1 ]]; then
    echo "Must have one argument" >&2
    return 1
fi
if [[ ! -e "src/$1" ]]; then
    echo "Design '$1' doesn't exist" >&2
    return 2
fi
if [[ ! -e "target/$1" ]]; then
    echo "Design '$1' hasn't been built! Use 'make $1' first" >&2
    return 2
fi

export NAME=$1
export SRC=$PWD/src/$1
export VENV=$SRC/.venv
export DECODER=$SRC/decoder

source $VENV/bin/activate
cd target/$1

python -m ectf25_design.gen_secrets global.secrets 1 2 3 4
docker run --rm -v $DECODER/:/decoder -v ./global.secrets:/global.secrets -v ./deadbeef_build:/out -e DECODER_ID=0xdeadbeef $NAME-decoder
