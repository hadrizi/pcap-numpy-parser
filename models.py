# utf-8
# Python 3.6



import numpy as np
import pandas as pd
import joblib

from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense, Dropout

import config



class BinaryClassifier():
    
    def __init__(self):
        """
        Initialization.
        """
        
        self.preproc_path = config.PREPROC_BINARY_PATH
        self.model_path = config.MODEL_BINARY_PATH
        self.create_preprocess()
        self.create_model()
        
        
    def create_preprocess(self):
        """
        Load pipeline to preprocess input data.
        """
        
        self.pipeline = joblib.load(self.preproc_path+"pipeline.pkl")
        self.pca_2 = joblib.load(self.preproc_path+"pca_2.pkl")
        self.kmeans_2 = joblib.load(self.preproc_path+"kmeans_2.pkl")
        self.pca_3 = joblib.load(self.preproc_path+"pca_3.pkl")
        self.kmeans_3 = joblib.load(self.preproc_path+"kmeans_3.pkl")
        self.pca_4 = joblib.load(self.preproc_path+"pca_4.pkl")
        self.kmeans_4 = joblib.load(self.preproc_path+"kmeans_4.pkl")
        
    
    def preprocess(self, X):
        """
        Preprocess data.
        """
        
        X = pd.DataFrame(X, columns=config.columns)
        X["protocol_type"] = X["protocol_type"].replace(config.protocol_type_dct)
        X["service"] = X["service"].replace(config.service_dct)
        X["flag"] = X["flag"].replace(config.flag_dct)
        
        return self.pipeline.transform(X)
    
    
    def create_model(self):
        """
        Create model and load weights.
        """
        
        self.detector = joblib.load(self.model_path+"model.pkl")
    
    
    def predict(self, X):
        """
        Predict attack.
        
        Parameters:
            X (np.array) - feature vector (n, )
            
        Returns:
            y (1/0) - attack
        """
        
        return self.detector.predict(self.preprocess([X]))[0]


    
class MultyClassifier():
    """
    Attack types classifier.
    """
    
    def __init__(self):
        """
        Initialization.
        """
        
        self.preproc_path = config.PREPROC_MULTY_PATH
        self.model_path = config.MODEL_MULTY_PATH
        self.create_preprocess()
        self.create_model()
    
        
    def create_preprocess(self):
        """
        Load pipeline to preprocess input data.
        """
        
        self.pipeline = joblib.load(self.preproc_path+"pipeline.pkl")
        self.pca_2 = joblib.load(self.preproc_path+"pca_2.pkl")
        self.kmeans_2 = joblib.load(self.preproc_path+"kmeans_2.pkl")
        self.pca_3 = joblib.load(self.preproc_path+"pca_3.pkl")
        self.kmeans_3 = joblib.load(self.preproc_path+"kmeans_3.pkl")
        self.pca_4 = joblib.load(self.preproc_path+"pca_4.pkl")
        self.kmeans_4 = joblib.load(self.preproc_path+"kmeans_4.pkl")
        
        
    def preprocess(self, X):
        """
        Preprocess data.
        """
        
        X = pd.DataFrame(X, columns=config.columns)
        X["protocol_type"] = X["protocol_type"].replace(config.protocol_type_dct)
        X["service"] = X["service"].replace(config.service_dct)
        X["flag"] = X["flag"].replace(config.flag_dct)
        
        X = self.pipeline.transform(X)
        X_cl = self.kmeans_2.transform(self.pca_2.transform(X))
        X = np.hstack([X, X_cl])
        X_cl = self.kmeans_3.transform(self.pca_3.transform(X))
        X = np.hstack([X, X_cl])
        X_cl = self.kmeans_4.transform(self.pca_4.transform(X))
        X = np.hstack([X, X_cl])
        
        return X
    
    
    def create_model(self):
        """
        Create model and load weights.
        """
        
        inp = Input(shape=(105, ), name="inp")
        dens_1 = Dense(256, activation='relu', name="dens_1")(inp)
        drop_1 = Dropout(0.7, name="drop_1")(dens_1)
        dens_2 = Dense(128, activation='sigmoid', name="dens_2")(drop_1)
        drop_2 = Dropout(0.5, name="drop_2")(dens_2)
        dens_3 = Dense(64, activation='sigmoid', name="dens_3")(drop_2)
        drop_3 = Dropout(0.3, name="drop_3")(dens_3)
        out = Dense(39, activation="softmax", name="out")(drop_3)
        
        
        self.detector = Model(inputs=inp, outputs=out)
        self.detector.compile(loss="categorical_crossentropy",
                              optimizer="adam",
                              metrics=["accuracy"])
        self.detector.load_weights(self.model_path + "weights/model")
    
    
    def predict(self, X):
        """
        Predict type of attack.
        
        Parameters:
            X (np.array) - feature matrix (m, n)
            
        Returns:
            y (np.array) - attack types vector (m, )
        """
        
        return self.detector.predict(self.preprocess(X)).argmax(1)


