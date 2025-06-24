from pathlib import Path
from setuptools import setup

ppp_common_path = Path(__file__).parent.parent / "decoder" / "ppp_common"

setup(install_requires=["loguru==0.7.3", f"ppp_common @ {ppp_common_path.as_uri()}"])
