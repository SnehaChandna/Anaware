import os
import requests
import matplotlib.pyplot as plt
import numpy as np

# Configuration
API_ENDPOINT = "http://localhost:5000/Image"
IMAGE_FOLDER = "./images"
PLOT_FILENAME = "malware_analysis_report.png"

def analyze_images():
    # Initialize counters
    malware_count = 0
    benign_count = 0
    malware_probs = []
    benign_probs = []
    
    # Get list of image files
    image_files = [f for f in os.listdir(IMAGE_FOLDER) 
                  if f.lower().endswith(('.png', '.jpg', '.jpeg'))]
    
    if not image_files:
        print(f"No images found in {IMAGE_FOLDER}")
        return

    # Process each image
    for idx, filename in enumerate(image_files, 1):
        file_path = os.path.join(IMAGE_FOLDER, filename)
        
        try:
            # Send request to API
            with open(file_path, 'rb') as f:
                response = requests.post(
                    API_ENDPOINT,
                    files={'file': (filename, f, 'image/jpeg')}
                )
            
            if response.status_code == 200:
                data = response.json()
                
                # Update counters
                if data['prediction'] == 'malicious':
                    malware_count += 1
                    malware_probs.append(data['malicious_probability'])
                else:
                    benign_count += 1
                    benign_probs.append(data['benign_probability'])
                
                print(f"Processed {idx}/{len(image_files)}: {filename} - {data['prediction']}")
            else:
                print(f"Error processing {filename}: {response.text}")
                
        except Exception as e:
            print(f"Failed to process {filename}: {str(e)}")
    
    # Calculate averages
    avg_malware_prob = np.mean(malware_probs) if malware_probs else 0
    avg_benign_prob = np.mean(benign_probs) if benign_probs else 0
    
    # Generate plots
    plt.figure(figsize=(12, 6))
    
    # First subplot - Counts
    plt.subplot(1, 2, 1)
    bars = plt.bar(['Malicious', 'Benign'], [malware_count, benign_count], color=['red', 'green'])
    plt.title('Malware vs Benign Count')
    plt.ylabel('Number of Images')
    
    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                 f'{int(height)}',
                 ha='center', va='bottom')

    # Second subplot - Probabilities
    plt.subplot(1, 2, 2)
    prob_bars = plt.bar(['Avg Malware Prob', 'Avg Benign Prob'], 
                       [avg_malware_prob, avg_benign_prob],
                       color=['darkred', 'darkgreen'])
    plt.title('Average Prediction Probabilities')
    plt.ylim(0, 1)
    
    # Add value labels on bars
    for bar in prob_bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                 f'{height:.2f}',
                 ha='center', va='bottom')

    # Save and show plot
    plt.tight_layout()
    plt.savefig(PLOT_FILENAME)
    print(f"\nReport saved as {PLOT_FILENAME}")

if __name__ == "__main__":
    analyze_images()