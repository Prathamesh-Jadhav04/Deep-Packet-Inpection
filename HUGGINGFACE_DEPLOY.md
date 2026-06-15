# DPI Console - Hugging Face All-in-One Deployment Guide

This guide explains how to deploy the entire project (Next.js Frontend + Python Backend) inside a single **Hugging Face Space** using the newly created multi-stage `Dockerfile`.

---

## 🚀 Step-by-Step Deployment

### Step 1: Create a Hugging Face Space
1. Go to [Hugging Face](https://huggingface.co/) and log in (or sign up for a free account).
2. Click on your profile picture at the top right, and click **New Space**.
3. Fill in the details:
   * **Space Name**: (e.g. `dpi-verdict-shield`)
   * **License**: Open-source (e.g., `mit` or `apache-2.0`)
   * **SDK**: **Docker** 🐳 (Do NOT choose Gradio or Streamlit).
   * **Docker Template**: **Blank**.
   * **Space Hardware**: **CPU Basic (Free)**.
   * **Visibility**: **Public** (recommended so anyone can view the demo).
4. Click **Create Space**.

---

### Step 2: Upload Project Files
Since Hugging Face Spaces are Git repositories under the hood, you can upload your files in two ways:

#### Option A: Using Git (Fastest & Easiest)
In your local command terminal (inside `D:\Deep Packet Inpection`), run:
```bash
# Initialize git if not done already
git init

# Add Hugging Face Space repository as remote (replace with your Space git link from HF page)
git remote add hf https://huggingface.co/spaces/<your-username>/<your-space-name>

# Add all files to staging
git add .

# Commit changes
git commit -m "feat: configure all-in-one docker deployment"

# Force push to Hugging Face (it will ask for your Hugging Face username and token/password)
git push -f hf master
```
*(Note: You can generate a git access token in your Hugging Face Account Settings under Access Tokens).*

#### Option B: Drag and Drop Files in Browser
1. Go to your Hugging Face Space page in your browser.
2. Under the **Files** tab, click **Add File** -> **Upload files**.
3. Drag and drop the following files and folders:
   * `dashboard/` (contains package.json, src, public, etc.)
   * `dpi_engine/` (contains python parser core)
   * `models/` (contains machine learning RandomForest models)
   * `Dockerfile` (contains the multi-stage build script)
   * `requirements.txt` (contains python dependencies)
   * `cli.py` (CLI runner)
   * `dpi_engine.py` (main entry file)
   * `test_dpi.pcap` (mock packet capture data)
4. Scroll down, write a commit message, and click **Commit changes**.

---

### Step 3: Wait for Build & Live Test
1. Go to the **App** tab on your Hugging Face Space page.
2. You will see a logs feed showing Node.js building the Next.js app, installing Python requirements, and starting the server.
3. Once the build status turns green (**Running**), your application is live!
4. The dashboard will load instantly.
5. Go to the **Live Capture** tab, select **`simulated`** from the interface list, and click **Start Capture**.
6. Real-time packet telemetry will flow across your dashboard 24/7!
