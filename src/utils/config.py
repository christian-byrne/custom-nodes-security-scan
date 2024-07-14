from pathlib import Path
import json

from typing import Union, Dict
from rich import print


class Config:
    PATH = None
    ROOT_PATH = None

    @staticmethod
    def get_proj_root():
        if Config.ROOT_PATH == None:
            Config.ROOT_PATH = Path(__file__).parent.parent.parent
        return Config.ROOT_PATH

    @staticmethod
    def get_config_path():
        if Config.PATH == None:
            path = Config.get_proj_root() / "config.json"
            if not path.exists():
                raise FileNotFoundError(f"Could not find config.json at {path}")
            Config.PATH = path

        return Config.PATH

    @staticmethod
    def get_config() -> Dict[str, str]:
        with open(Config.get_config_path(), "r") as f:
            return json.loads(f.read())

    @staticmethod
    def write_config(config_data):
        with open(Config.get_config_path(), "w") as f:
            json.dump(config_data, f, indent=4)

        return True

    @staticmethod
    def update_config_property(key: str, value: Union[str, Path]):
        if not isinstance(key, str):
            raise TypeError(f"Cannot use {type(key)} for config keys")
        if isinstance(value, Path):
            value = str(value.resolve())

        config_data = Config.get_config()
        config_data[key] = value
        Config.write_config(config_data)

    def __getitem__(self, key, fallback=None):
        if fallback:
            return Config.get_config().get(key, fallback)
        if key not in Config.get_config():
            raise KeyError(
                f"Could not find key {key} in config. Existing keys: {Config.get_config().keys()}"
            )
        return Config.get_config()[key]
