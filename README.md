# Project README

This project is structured into three main folders: `frontend`, `backend`, and `server`. Each folder contains a different part of the application, and all three components need to be running simultaneously for the project to function correctly. Below are the instructions to set up and run each part of the project.

## Project Structure

- **frontend**: Contains the frontend code for the project.
- **backend**: Contains the backend code for the project.
- **server**: Contains the Flask servers (both `bigram_server.py` and `flask_server.py`).

## Prerequisites

Before running the project, ensure you have the following installed:

- **Node.js** and **npm** (for frontend and backend)
- **Python** and **pip** (for Flask servers)
- **Conda** (for managing Python environments)
- **Git** (for cloning repositories)

## Setup Instructions

### 1. Frontend Setup

1. Navigate to the `frontend` folder:
   ```bash
   cd frontend
   ```

2. Install the required dependencies:
   ```bash
   npm install
   ```

3. Run the frontend development server:
   ```bash
   npm run dev
   ```

   The frontend should now be running on a local development server (usually `http://localhost:3000`).

### 2. Backend Setup

1. Navigate to the `backend` folder:
   ```bash
   cd backend
   ```

2. Install the required dependencies:
   ```bash
   npm install
   ```

3. Run the backend development server:
   ```bash
   npm run dev
   ```

   The backend should now be running on a local development server (usually `http://localhost:5000`).

### 3. Flask Server Setup

#### Cloning the MaleX Repository

1. Navigate to the `server` folder:
   ```bash
   cd server
   ```

2. Clone the MaleX repository:
   ```bash
   git clone https://github.com/Mayachitra-Inc/MaleX.git
   ```

3. Navigate into the cloned repository:
   ```bash
   cd MaleX
   ```

#### Environment Setup

1. Create and activate the Conda environment for the `main` server using the `main.yml` file:
   ```bash
   conda env create -f main.yml
   conda activate main
   ```

2. Create and activate the Conda environment for the `malix` server using the `malix.yml` file:
   ```bash
   conda env create -f malix.yml
   conda activate malix
   ```

#### Running the Flask Servers

1. **Running the `main` server (`flask_server.py`)**:
   - Ensure the `main` environment is activated.
   - Run the server:
     ```bash
     python flask_server.py
     ```
   - Note the port on which this server is running (e.g., `http://localhost:5001`).

2. **Running the `malix` server (`bigram_server.py`)**:
   - Ensure the `malix` environment is activated.
   - Run the server:
     ```bash
     python bigram_server.py
     ```
   - Note the port on which this server is running (e.g., `http://localhost:5002`).

### 4. Configuring the Backend

1. Open the `backend/index.ts` file.
2. Locate line number 25 where the `FLASK_ENDPOINT` variable is defined.
3. Update the `FLASK_ENDPOINT` variable with the URL of the `main` server (e.g., `http://localhost:5001`).

### 5. Running the Project

1. Ensure all three servers (frontend, backend, and Flask servers) are running.
2. Open the frontend URL (usually `http://localhost:3000`) in your browser.
3. The project should now be fully functional.

## Troubleshooting

- **Port Conflicts**: If any of the servers fail to start due to port conflicts, ensure that the ports are free or update the port numbers in the respective server files.
- **Environment Issues**: If you encounter issues with the Conda environments, try recreating them using the provided `.yml` files.
- **Dependency Issues**: If `npm install` or `pip install` fails, ensure that you have the correct versions of Node.js, npm, Python, and pip installed.

## Conclusion

Once all the components are set up and running, you should have a fully functional project with a frontend, backend, and Flask servers working together. If you encounter any issues, refer to the troubleshooting section or consult the documentation for the respective technologies used in this project.

Happy coding! 🚀
