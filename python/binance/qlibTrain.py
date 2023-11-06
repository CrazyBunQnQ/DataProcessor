import qlib
from qlib.config import REG_CN
from qlib.contrib.model.gbdt import LGBModel
from qlib.contrib.data.handler import Alpha158
from qlib.contrib.strategy.strategy import TopkDropoutStrategy
from qlib.contrib.evaluate import (
    backtest as normal_backtest,
    risk_analysis,
)
from qlib.utils import exists_qlib_data, init_instance_by_config

# Load data
qlib.init(provider_uri='./Data/')
# Load data into Qlib format
D.features(minute_df_cleaned, 'minute_BTCUSDT')

# Define dataset config
dataset_config = {
    "class": "DatasetH",
    "module_path": "qlib.data.dataset",
    "kwargs": {
        "handler": {
            "class": "Alpha158",
            "module_path": "qlib.contrib.data.handler",
            "kwargs": {
                "start_time": "2023-10-31",
                "end_time": "2023-11-01",
                "fit_start_time": "2023-10-31",
                "fit_end_time": "2023-11-01",
                "instruments": 'minute_BTCUSDT',
            },
        },
        "segments": {
            "train": ("2023-10-31", "2023-11-01"),
        },
    },
}

dataset = init_instance_by_config(dataset_config)

# Define model config
from qlib.contrib.model.gbdt import LGBModel
from qlib.utils import flatten_dict

# Define model config
model_config = {
    "class": "LGBModel",
    "module_path": "qlib.contrib.model.gbdt",
    "kwargs": {
        "loss": "mse",
        "colsample_bytree": 0.8879,
        "learning_rate": 0.0421,
        "subsample": 0.8789,
        "lambda_l1": 205.6999,
        "lambda_l2": 580.9768,
        "max_depth": 8,
        "num_leaves": 210,
        "num_threads": 20,
    },
}

model = init_instance_by_config(model_config)
model.fit(dataset)

# Predict
pred = model.predict(dataset)
print(pred)
