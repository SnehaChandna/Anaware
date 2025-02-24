from flask import Flask, request, jsonify
import numpy as np
import joblib
from skimage.feature import local_binary_pattern, graycomatrix, graycoprops
from scipy.stats import skew, kurtosis, entropy
from skimage import color, feature
from scipy.fftpack import dct
import cv2
import pywt
from scipy.ndimage import median_filter
import warnings
import socket
import pickle
from skimage import io
from io import BytesIO
import pandas as pd
import os
from ultralytics import YOLO
import tempfile
import magic
from PIL import Image, ImageFile
import hashlib

# Configure PIL to prevent decompression bomb attacks
ImageFile.LOAD_TRUNCATED_IMAGES = False

warnings.filterwarnings("ignore")

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # Limit uploads to 10MB
ALLOWED_EXTENSIONS_IMAGE = {'png', 'jpg', 'jpeg'}
ALLOWED_EXTENSIONS_FILES = {'exe', 'dll', 'bin'}

# Load model and scaler
model = joblib.load('xgb_model.pkl')
scaler = joblib.load('scaler.pkl')
model_YOLO = YOLO("YOLO/mal_detect.pt")  # load the best model
UPLOAD_FOLDER = tempfile.mkdtemp()

# Configuration
MALEX_HOST = "127.0.0.1"
MALEX_PORT = 65432
SOCKET_TIMEOUT = 30

def request_image(command, file_path):
    """Improved socket communication with error handling"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(SOCKET_TIMEOUT)
            client_socket.connect((MALEX_HOST, MALEX_PORT))
            
            request = {"command": command, "file_path": file_path}
            client_socket.sendall(pickle.dumps(request))

            # Handle large responses
            response_data = b""
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                
            return pickle.loads(response_data)
            
    except (socket.timeout, ConnectionRefusedError) as e:
        return {"error": f"Malex service unavailable: {str(e)}"}
    except Exception as e:
        return {"error": f"Communication error: {str(e)}"}

class SecureFileHandler:
    @staticmethod
    def validate_file_content(file_data, allowed_types):
        """Validate file content using magic numbers"""
        try:
            mime = magic.from_buffer(file_data, mime=True)
            if allowed_types == 'image':
                if mime not in ['image/jpeg', 'image/png']:
                    return False
            elif allowed_types == 'executable':
                if mime not in ['application/x-dosexec', 'application/octet-stream']:
                    return False
            return True
        except Exception as e:
            print(f"MIME validation failed: {str(e)}")
            return False

    @staticmethod
    def safe_image_processing(image_data):
        """Secure image processing with PIL"""
        try:
            # Verify image integrity
            img = Image.open(BytesIO(image_data))
            img.verify()
            
            # Reopen verified image
            img = Image.open(BytesIO(image_data))
            
            # Prevent decompression bombs
            if img.width * img.height > 10_000_000:  # 10MP limit
                raise ValueError("Image dimensions too large")
                
            return img
        except Exception as e:
            print(f"Image security check failed: {str(e)}")
            return None

class FeatureExtractor:
    @staticmethod
    def extract_all_features(image_data):
        """Process image data securely from memory"""
        try:
            # Security checks
            if not SecureFileHandler.validate_file_content(image_data, 'image'):
                return None

            # Secure image processing
            pil_image = SecureFileHandler.safe_image_processing(image_data)
            if pil_image is None:
                return None

            # Convert to numpy array
            image = np.array(pil_image)
            
            # Handle RGBA images
            if len(image.shape) == 3 and image.shape[2] == 4:
                image = cv2.cvtColor(image, cv2.COLOR_RGBA2RGB)
                
            # Convert to grayscale if needed
            if len(image.shape) == 3:
                image_gray = color.rgb2gray(image)
            else:
                image_gray = image
                
            image_gray = (image_gray * 255).astype(np.uint8)
            
            features = {}
            
            # Basic features
            features.update(FeatureExtractor.extract_histogram_features(image_gray))
            features.update(FeatureExtractor.extract_glcm_features(image_gray))
            features.update(FeatureExtractor.extract_lbp_features(image_gray))
            features.update(FeatureExtractor.extract_dct_features(image_gray))
            features.update(FeatureExtractor.extract_edge_features(image_gray))
            
            # Advanced features
            features.update(FeatureExtractor.extract_wavelet_features(image_gray))
            features.update(FeatureExtractor.extract_higher_order_stats(image_gray))
            features.update(FeatureExtractor.extract_spam_features(image_gray))
            features.update(FeatureExtractor.extract_noise_features(image_gray))
            features.update(FeatureExtractor.extract_fourier_features(image_gray))
            
            # Color features
            if len(image.shape) == 3:
                features.update(FeatureExtractor.extract_color_features(image))
                
            return features
            
        except Exception as e:
            print(f"Feature extraction error: {str(e)}")
            return None
        
    # Feature extraction methods
    @staticmethod
    def extract_histogram_features(image_array):
        hist, _ = np.histogram(image_array.flatten(), bins=256, range=[0, 256])
        return {
            'hist_mean': np.mean(hist),
            'hist_std': np.std(hist),
            'hist_skew': skew(hist),
            'hist_kurtosis': kurtosis(hist)
        }

    @staticmethod
    def extract_glcm_features(image_array):
        glcm = graycomatrix(image_array, distances=[1], angles=[0], levels=256, symmetric=True, normed=True)
        return {
            'contrast': graycoprops(glcm, 'contrast')[0, 0],
            'dissimilarity': graycoprops(glcm, 'dissimilarity')[0, 0],
            'homogeneity': graycoprops(glcm, 'homogeneity')[0, 0],
            'energy': graycoprops(glcm, 'energy')[0, 0],
            'correlation': graycoprops(glcm, 'correlation')[0, 0]
        }

    @staticmethod
    def extract_lbp_features(image_array):
        radius = 3
        n_points = 8 * radius
        lbp = local_binary_pattern(image_array, n_points, radius, method='uniform')
        hist, _ = np.histogram(lbp.ravel(), bins=np.arange(0, n_points + 3), range=(0, n_points + 2))
        hist = hist.astype("float")
        hist /= (hist.sum() + 1e-7)
        return {f'lbp_hist_{i}': v for i, v in enumerate(hist)}

    @staticmethod
    def extract_dct_features(image_array):
        dct_array = dct(dct(image_array.T, norm='ortho').T, norm='ortho')
        return {
            'dct_mean': np.mean(dct_array),
            'dct_std': np.std(dct_array),
            'dct_skew': skew(dct_array.flatten()),
            'dct_kurtosis': kurtosis(dct_array.flatten())
        }

    @staticmethod
    def extract_edge_features(image_array):
        edges_sobel = feature.canny(image_array, sigma=1)
        edges_canny = feature.canny(image_array, sigma=2)
        return {
            'edges_sobel_mean': np.mean(edges_sobel),
            'edges_sobel_std': np.std(edges_sobel),
            'edges_canny_mean': np.mean(edges_canny),
            'edges_canny_std': np.std(edges_canny)
        }

    @staticmethod
    def extract_wavelet_features(image_array):
        wavelets = ['haar', 'db1', 'db2']
        features = {}
        
        for wavelet in wavelets:
            coeffs = pywt.wavedec2(image_array, wavelet, level=3)
            
            for level, coeff_set in enumerate(coeffs):
                if level == 0:
                    features.update({
                        f'{wavelet}_L{level}_mean': np.mean(coeff_set),
                        f'{wavelet}_L{level}_std': np.std(coeff_set),
                        f'{wavelet}_L{level}_entropy': entropy(np.abs(coeff_set.flatten()))
                    })
                else:
                    for idx, direction in enumerate(['H', 'V', 'D']):
                        sub_coeff = coeff_set[idx]
                        features.update({
                            f'{wavelet}_L{level}_{direction}_mean': np.mean(sub_coeff),
                            f'{wavelet}_L{level}_{direction}_std': np.std(sub_coeff),
                            f'{wavelet}_L{level}_{direction}_entropy': entropy(np.abs(sub_coeff.flatten()))
                        })
        return features

    @staticmethod
    def extract_higher_order_stats(image_array):
        median_filtered = median_filter(image_array, size=3)
        residual = image_array - median_filtered
        return {
            'residual_mean': np.mean(residual),
            'residual_std': np.std(residual),
            'residual_skew': skew(residual.flatten()),
            'residual_kurtosis': kurtosis(residual.flatten()),
            'residual_entropy': entropy(np.abs(residual.flatten())),
        }

    @staticmethod
    def extract_spam_features(image_array, order=2):
        features = {}
        hdiff = np.diff(image_array, axis=1)
        vdiff = np.diff(image_array, axis=0)
        
        for diff, direction in [(hdiff, 'horizontal'), (vdiff, 'vertical')]:
            T = 3
            diff_normalized = np.clip(diff, -T, T)
            hist, _ = np.histogram(diff_normalized, bins=2*T+1, range=(-T-0.5, T+0.5))
            hist = hist / np.sum(hist)
            features.update({f'spam_{direction}_hist_{i}': v for i, v in enumerate(hist)})
        return features

    @staticmethod
    def extract_noise_features(image_array):
        features = {}
        kernels = {
            'sobel_x': np.array([[-1, 0, 1], [-2, 0, 2], [-1, 0, 1]]),
            'sobel_y': np.array([[-1, -2, -1], [0, 0, 0], [1, 2, 1]]),
            'laplacian': np.array([[0, 1, 0], [1, -4, 1], [0, 1, 0]])
        }
        
        for name, kernel in kernels.items():
            residual = cv2.filter2D(image_array, -1, kernel)
            features.update({
                f'{name}_residual_mean': np.mean(np.abs(residual)),
                f'{name}_residual_std': np.std(residual),
                f'{name}_residual_entropy': entropy(np.abs(residual.flatten()))
            })
        return features

    @staticmethod
    def extract_color_features(image):
        features = {}
        if len(image.shape) == 3:
            ycbcr = cv2.cvtColor(image, cv2.COLOR_RGB2YCrCb)
            for i, channel in enumerate(['y', 'cb', 'cr']):
                features.update({
                    f'ycbcr_{channel}_mean': np.mean(ycbcr[:,:,i]),
                    f'ycbcr_{channel}_std': np.std(ycbcr[:,:,i]),
                    f'ycbcr_{channel}_entropy': entropy(ycbcr[:,:,i].flatten())
                })
            
            hsv = cv2.cvtColor(image, cv2.COLOR_RGB2HSV)
            for i, channel in enumerate(['h', 's', 'v']):
                features.update({
                    f'hsv_{channel}_mean': np.mean(hsv[:,:,i]),
                    f'hsv_{channel}_std': np.std(hsv[:,:,i]),
                    f'hsv_{channel}_entropy': entropy(hsv[:,:,i].flatten())
                })
        return features

    @staticmethod
    def extract_fourier_features(image_array):
        fft = np.fft.fft2(image_array)
        fft_shift = np.fft.fftshift(fft)
        magnitude_spectrum = np.abs(fft_shift)
        
        h, w = magnitude_spectrum.shape
        center_h, center_w = h//2, w//2
        
        regions = {
            'low': magnitude_spectrum[center_h-h//8:center_h+h//8, center_w-w//8:center_w+w//8],
            'mid': magnitude_spectrum[center_h-h//4:center_h+h//4, center_w-w//4:center_w+w//4],
            'high': magnitude_spectrum
        }
        
        features = {}
        for region_name, region in regions.items():
            features.update({
                f'fft_{region_name}_mean': np.mean(region),
                f'fft_{region_name}_std': np.std(region),
                f'fft_{region_name}_entropy': entropy(region.flatten())
            })
        return features

def allowed_file_quick_scan(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_FILES

def allowed_file_Image_scan(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_IMAGE

@app.route('/Image', methods=['POST'])
def predict():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    if file and allowed_file_Image_scan(file.filename):
        try:
            # Read file data directly into memory
            file_data = file.read()
            
            # Security validation
            if not SecureFileHandler.validate_file_content(file_data, 'image'):
                return jsonify({'error': 'Invalid file content'}), 400
            
            # Extract features
            features = FeatureExtractor.extract_all_features(file_data)
            if features is None:
                return jsonify({'error': 'Feature extraction failed'}), 500
                
            # Convert to DataFrame for scaling
            features_df = pd.DataFrame([features])
            
            # Scale features
            scaled_features = scaler.transform(features_df)
            
            # Make prediction
            prediction = model.predict(scaled_features)
            proba = model.predict_proba(scaled_features)
            
            return jsonify({
                'prediction': 'malicious' if prediction[0] == 0 else 'benign',
                'confidence': float(np.max(proba)),
                'malicious_probability': float(proba[0][0]),
                'benign_probability': float(proba[0][1])
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        finally:
            # Ensure file buffer is cleared
            file.close()
            
    return jsonify({'error': 'Invalid file type'}), 400

@app.route('/deep_scan', methods=['POST'])
def deep_scan():
    return predict()

@app.route('/quick_scan', methods=['POST'])
def quick_scan():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    if not allowed_file_quick_scan(file.filename):
        return jsonify({"error": "Invalid file type"}), 400

    try:
        # Use temporary file with auto-cleanup
        with tempfile.NamedTemporaryFile(dir=UPLOAD_FOLDER, delete=True) as tmp_file:
            file.save(tmp_file.name)
            
            # Get DCT image from Malex service
            img_bigramdct = request_image("getDCTImage", tmp_file.name)
            
            if 'error' in img_bigramdct:
                return jsonify({"error": img_bigramdct['error']}), 502
            
            # Validate response format
            if not isinstance(img_bigramdct, np.ndarray) or img_bigramdct.shape != (256, 256):
                return jsonify({"error": "Invalid DCT image format"}), 502

            # Process with YOLO model
            result = model_YOLO(img_bigramdct)[0]
            p = result.probs.data.cpu().numpy().tolist()
            
            return jsonify({
                "status": "success",
                "malware_probability": p[1],
                "benign_probability": p[0],
                "confidence": max(p)
            })
            
    except Exception as e:
        return jsonify({"error": f"Processing error: {str(e)}"}), 500

@app.route('/', methods=['GET'])
def health_check():
    return jsonify({
        "status": "success",
        "message": "Successfully connected to the server",
        "service": "Malware Detection API",
        "version": "1.0"
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)  # Disable debug in production