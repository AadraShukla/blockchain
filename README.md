🏥 Medical Records Blockchain
A secure, decentralized system for storing and retrieving medical records using blockchain technology with hybrid encryption (RSA + AES).
✨ Key Features

🔐 Hybrid Encryption: Combines RSA (2048-bit) and AES-256 encryption for optimal security and performance
⛓️ Blockchain Storage: Immutable, tamper-proof medical record storage with proof-of-work validation
🔒 Data Privacy: End-to-end encryption ensures only authorized parties can access sensitive medical data
👨‍⚕️ Access Control: Role-based access with doctor ID verification
💾 Persistent Storage: Automatic blockchain serialization with pickle for data persistence
🌐 Web Interface: Clean, user-friendly Flask-based dashboard for record submission and retrieval

🛠️ Tech Stack

Backend: Flask (Python)
Blockchain: Custom implementation with SHA-256 hashing
Encryption: RSA (public/private key) + AES-256
Storage: Pickle for blockchain persistence

🚀 Getting Started
--Prerequisites
pip install flask cryptography
--Installation
Clone the repository
git clone https://github.com/yourusername/medical-records-blockchain.git
cd medical-records-blockchain
--Run the application
python projectself.py
--Access the dashboard at http://localhost:5000

📋 Usage
Submit Medical Records
<img width="1911" height="980" alt="image" src="https://github.com/user-attachments/assets/977e5be7-bd8c-4610-9123-928a5da0f569" />

Navigate to the submission page
<img width="1911" height="988" alt="image" src="https://github.com/user-attachments/assets/67bd08a3-fcdf-4cae-8627-01ccd42eb188" />

Enter user ID, details, and medical records
Records are automatically encrypted and added to the blockchain

Retrieve Records

Enter doctor ID and patient user ID
<img width="1906" height="987" alt="image" src="https://github.com/user-attachments/assets/fbcb44cd-cdfd-4e44-893d-8012669d43a5" />

System validates doctor credentials
Decrypts and displays authorized medical records
<img width="1912" height="986" alt="image" src="https://github.com/user-attachments/assets/87f96c48-cd22-474d-8652-28f5d88b0457" />

🔑 Security Features

Double-layer encryption: AES key encrypted with RSA public key
Chain validation: Ensures blockchain integrity
Proof-of-work: Prevents tampering with difficulty level (5 leading zeros)
Access authentication: Only validated doctor IDs can retrieve records

⚠️ Security Note
This is a demonstration project. For production use, implement additional security measures such as:
--Secure key management system
--User authentication and authorization
--HTTPS/TLS encryption
--Database backup and recovery
--Audit logging



📄 License
MIT License - feel free to use this project for learning and development purposes.
🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
