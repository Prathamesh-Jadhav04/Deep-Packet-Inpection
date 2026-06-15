import os
import joblib

def main():
    model_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "eti_rf_model.pkl"))
    onnx_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models", "eti_model.onnx"))
    
    if not os.path.exists(model_path):
        print(f"Error: RandomForest model not found at {model_path}")
        print("Please train the model first by running scratch/train_eti_model.py")
        return
        
    print(f"Loading RandomForest model from {model_path}...")
    model = joblib.load(model_path)
    
    try:
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType
    except ImportError:
        print("Error: 'skl2onnx' is required for exporting to ONNX.")
        print("Please install it using: pip install skl2onnx")
        return

    # Define input type: 17 float features representing the ETI features
    # (10 normalised size buckets + mean_sz + var_sz + mean_iat + var_iat + cv_iat + burst_count + avg_burst_sz)
    initial_type = [('float_input', FloatTensorType([None, 17]))]
    
    print("Converting RandomForest model to ONNX format...")
    # target_opset=12 or similar for compatibility
    onnx_model = convert_sklearn(model, initial_types=initial_type, target_opset=12)
    
    print(f"Saving ONNX model to {onnx_path}...")
    os.makedirs(os.path.dirname(onnx_path), exist_ok=True)
    with open(onnx_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
        
    print("ONNX model exported successfully!")

if __name__ == "__main__":
    main()
