# eCTF Exemplars
This repository holds exemplar implementations of the 2025 Embedded Capture
the Flag (eCTF) Competition.

Information about the eCTF can be found at https://ectf.mitre.org and more
information aobut the 2025 eCTF competition can be found at
https://rules.ectf.mitre.org/2025.

## Setup
Requires:
* Python >=3.12
* Docker Desktop


## Layout
There are two main directories of interest. First is `tools/`, which holds
a Python package that automates interaction with the various desings. This
will be installed as `ectf25` in the created virtual environments.

Second is `src`, which holds the source code to four implementations of the
2025 eCTF challenge. The first is `src/insecure`, which contains the reference
design that implements only the functional satellite TV system with no
intention of addressing the security requirements. The other three are
`src/design1`, `src/design2`, and `src/design3`, which contain three full
attempts at completing the competition, each demonstrating more success than
the last.

## Use
### 0. Clone Repository
First, you must clone the repository.

If you have git, you can use it directly, otherwise, you can use Docker to clone it for you:

```bash
# with git
git clone https://github.com/janisbent/ectf-workshop.git
# without git
docker run -v ./workshop:/workshop alpine/git clone https://github.com/janisbent/ectf-workshop.git /workshop
```


```powershell
mkdir -p ~\Desktop\workshop
cd ~\Desktop\workshop
```

```powershell
$design = "insecure"
$serial = "COM4"
```

```powershell
python -m pip install .\src\$design\design .\tools
docker build -t $design-decoder src\$design\decoder
mkdir $design
cd $design
```

```powershell
python -m ectf25_design.gen_secrets global.secrets 1 2 3 4
```

```powershell
docker run --rm -v C:\Users\Student\Desktop\workshop\src\$design\decoder:/decoder -v .\global.secrets:/global.secrets -v .\0xdeadbeef_build:/out -e DECODER_ID=0xdeadbeef $design-decoder
```

```powershell
python -m ectf25_design.gen_subscription always_1.sub 0xdeadbeef 0 0xffffffffffffffff 1
```

```powershell
python -m ectf25.utils.flash .\desdbeef.build\max78000.bin $serial
```

```powershell
python -m ectf25_design.tv.list $serial
```

```powershell
python -m ectf25_design.tv.subscribe .\always_1.sub $serial
```

```powershell
python -m ectf25_design.utils.tester --secrets .\global.secrets --port $serial --delay 0.5 rand --channels 1
```

### 1. Build Enviornment
Each design can be built and run independently. To build the environment for a
design, run:

```bash
make <design>
```

Where `<design>` is one of the directories in `src` (e.g., `insecure`). This
will set up the environment to build a particular design, building both the
Docker image that will be used to build the firmware as well as a virtual
Python environment.  NOTE: The first build of this can take up to 10 minutes
to complete

### 2. Activate Environment
Once the design is made, you can activate the environment using:

```bash
source activate.sh <design>
```

This will activate the virtual environment, move you into the proper target
directory, and define a few helpful commands for future steps.

At any time, you can deactivate the environment and move back to the root with:

```bash
deactivate && cd ../..
```

### 3. Generate Secrets
Next, we can run through the commands to build a deployment.

First, we need to generate the system secrets with:

```bash
gen_secrets
```

This will output the file `global.secrets` that contains all of the secrets
needed by other steps.

### 4. Build Decoder
Next, we can start building the firmware for individual decoders with:
```bash
build_decoder <decoder_id>
```

Where `<decoder_id>` is a 32b (up to 8-digit) hexadecimal number
(e.g., 0x12345678 or 0xdeadbeef). This will generate a directory
`decoder_id.build` that contains the firmware image for the newly-built
decoder.

This step can be repeated to make additional decoders so long as they each
have a unique `decoder_id`.

### 5. Generate Subscription
Next, we can generate subscriptions for the newly-built decoder with:

```bash
gen_subscription <subscription> <decoder_id> <start> <end> <channel>
```

Where `<subscription>` is the name of the file to create, `<decoder_id>` is the
ID of one of the built decoders, `<start>` and `<end>` are 64b (up to 16-digit)
hexadecimal numbers for the start and end timestamps, and `<channel>` is the
channel being subscribed to (valid options: 1, 2, 3, or 4).

For example, to create a subscription always_1.sub for decoder 0xdeadbeef that will always be
valid for channel 1, you can run:

```bash
gen_subscription always_1.sub 0xdeadbeef 0 0xffffffffffffffff 1
```

### 6. Flash Firmware
We can now flash the firmware onto the boards with:

```bash
flash <decoder_id> <port>
```

Where the `<decoder_id>` is the ID of one of the built decoders and `<port>`
is the serial port of the target board (see `https://rules.ectf.mitre.org/2025/getting_started/boot_reference.html` for help finding the port).

NOTE: The board must be in update mode to flash. You can put it in update mode
by holding the button SW1 on the board while you plug it in to USB.

### 7. Interact with Decoder
With the decoder flashed, you can now interract with it.

The three commands available are:

#### 7.1 List
You can list all subscribed channels with:

```bash
list <port>
```

Where `<port>` is the serial port to the decoder.

#### 7.2 Subscribe
You can subscribe the decoder to a new channel or update the existing channel
subscription with:

```bash
subscribe <port> <subscription>
```

Where `<port>` is the serial port to the decoder and `<subscription>` is the
generated subscription.

#### 7.3 Run
Finally, you can run the TV with:

```bash
run <port> <channel>
```

Where `<port>` is the serial port to the decoder and `<channel>` is the
channel number to generate frames on.

This will run the Python encoder to encode the frames, sending them to the
decoder running on the boards and printing the response.
