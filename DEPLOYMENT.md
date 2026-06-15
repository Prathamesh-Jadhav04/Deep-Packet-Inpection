# DPI Console - Option 2 (Split Deployment) Guide

This guide explains how to deploy the Next.js Frontend and the Python Backend separately for **100% free** and run it 24/7.

---

## 🚀 Phase 1: Deploy Next.js Frontend on Vercel (Free)

Vercel is the default hosting provider for Next.js, and it is completely free.

1. **Push your code to GitHub**:
   * Create a new repository on GitHub (private or public).
   * Push your entire project folder to this repository.

2. **Deploy on Vercel**:
   * Go to [Vercel](https://vercel.com/) and sign in using your GitHub account.
   * Click **Add New** -> **Project**.
   * Import your GitHub repository.
   * In the **Configure Project** settings:
     * Set **Root Directory** to `dashboard` (since your Next.js app is inside the `/dashboard` folder).
     * Leave the build settings as default (Vercel automatically detects Next.js).
   * Click **Deploy**.
   * *Within 1-2 minutes, you will get your live frontend URL (e.g. `https://dpi-dashboard.vercel.app`).*

---

## 🐳 Phase 2: Deploy Python Backend on Hugging Face (Docker Space - Free)

Hugging Face Spaces allow you to deploy custom Docker containers for free 24/7.

1. **Create Hugging Face Space**:
   * Go to [Hugging Face](https://huggingface.co/) and sign in.
   * Click on your profile picture at the top right and select **New Space**.
   * Give it a name (e.g., `dpi-backend`).
   * Select **Docker** as the SDK (Do NOT select Gradio or Streamlit).
   * Select **Blank** as the template.
   * Choose **Public** visibility (required for Vercel to communicate with it).
   * Click **Create Space**.

2. **Upload Files**:
   * Once the Space is created, go to the **Files** tab.
   * Upload the following files and folders from your project root:
     * `dpi_engine/` (directory containing python parsers, classifiers, etc.)
     * `models/` (directory containing `eti_rf_model.pkl` and `eti_model.onnx`)
     * `Dockerfile` (already created in the project root)
     * `requirements.txt` (already created in the project root)
     * `cli.py` (file)
     * `dpi_engine.py` (file)
     * `test_dpi.pcap` (pre-built test packets file)
   * Hugging Face will automatically detect the `Dockerfile` and begin building the container.
   * *Once built, your API server will be live at: `https://<your-username>-<your-space-name>.hf.space`.*

---

## 🔗 Phase 3: Connect Frontend to Backend

Now, link your Next.js frontend to the Python backend API:

1. Open your live Next.js Vercel website link.
2. Go to the **Settings** tab.
3. Under the **DPI Engine Connection** card, in the **API Server Base URL** input field, enter your Hugging Face Space URL.
   * *Example*: `https://prathamesh-dpi-backend.hf.space`
4. Click **Apply**.
5. Go to the **Overview** tab or check the bottom-right sidebar. The connection status should now change to **Connected** (Green badge).
6. Go to the **Live Capture** tab, choose **simulated** from the Interface dropdown, and click **Start Capture**.
7. *Packets will start streaming live into your dashboard 24/7!*
