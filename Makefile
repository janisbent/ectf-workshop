
DESIGNS=insecure
BIN=$(PWD)/bin

$(DESIGNS):
$(DESIGNS):
	python3 -m venv src/$@/.venv --prompt $@
	src/$@/.venv/bin/python -m pip install ./tools/ src/$@/design
	docker build -t $@-decoder src/$@/decoder
	mkdir -p target/$@

clean:
	rm -rf src/*/.venv target src/*/design/*.egg-info src/*/decoder/build