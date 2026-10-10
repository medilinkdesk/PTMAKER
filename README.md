# Garment Inventory Verification Web App

Mobile-friendly and laptop-compatible Progressive Web App (PWA) for garment suppliers, inventory managers, and warehouse staff to upload Excel inventory sheets, scan barcodes using camera or USB/Bluetooth scanners, verify MRP/Size/Quantity discrepancies, record extra unlisted stock, and export updated Excel files.

Hosted live on GitHub Pages with complete client-side processing (no backend server required).

---

## 🌟 Key Features

* **Excel File Upload & Parsing**: Reads `.xlsx`, `.xls`, and `.csv` files using SheetJS.
* **Smart Column Mapping**: Automatically detects and maps Excel columns (`EAN`, `Quantity`, `MRP`, `Size`, `Brand`, `Design #`, `Nature`, `Purchase Rate`, etc.) with manual override support.
* **Barcode Scanning Options**:
  * **Camera Scanning**: Integrated high-speed video barcode scanner using ZXing browser library.
  * **USB / Bluetooth Barcode Gun**: Supports continuous focus keyboard-emulating hardware scanners with automatic search on Enter key.
* **Discrepancy Tracking**:
  * **Quantity Verification**: Track expected vs scanned vs actual physical stock. Supports batch quantity overrides, undo last scan, and excess stock alerts.
  * **MRP Verification**: Compare printed tag MRP against expected Excel MRP. Easily log MRP mismatches.
  * **Size Verification**: Verify tag size against expected size.
  * **Safe Duplicate Barcode Handler**: If a single barcode is used across multiple sizes/rows in Excel, the app prompts the user to select the specific item row rather than silently merging them.
* **Unlisted / Extra Stock Recording**: Record items found in physical shipment that do not exist in the supplier Excel sheet.
* **Offline PWA & Local Persistence**: Auto-saves every scan and modification to IndexedDB. Resume saved sessions anytime or export/import JSON session backups.
* **Verified Excel Export**: Downloads the original supplier Excel sheet with all original columns and rows preserved, appended with 10 detailed verification columns:
  1. `Scanned Qty`
  2. `Actual Physical Qty`
  3. `Qty Difference`
  4. `Actual MRP`
  5. `MRP Verification Status`
  6. `Actual Size`
  7. `Size Verification Status`
  8. `Actual Brand / Item`
  9. `Verification Status`
  10. `Remarks`

---

## 🛠️ Technology Stack

* **Frontend**: HTML5, CSS3, JavaScript (ES6+)
* **Excel Engine**: SheetJS (`xlsx`)
* **Barcode Scanner Engine**: ZXing Browser Library (`@zxing/library`)
* **Local Persistence**: IndexedDB & LocalStorage
* **Audio Synth Engine**: Web Audio API (Synthesized Beep Sounds)
* **PWA & Offline Capability**: Service Worker & Web App Manifest

---

## 🚀 GitHub Pages Deployment Workflow

1. **Create GitHub Repository**:
   Create a new public or private repository on GitHub (e.g., `garment-inventory-verify`).

2. **Upload Repository Files**:
   Push all project files to the root of your default branch (`main`):
   ```
   index.html
   styles.css
   app.js
   manifest.json
   service-worker.js
   README.md
   ```

3. **Enable GitHub Pages**:
   * Navigate to **Settings** → **Pages** in your GitHub repository.
   * Under **Build and deployment** → **Source**, choose **Deploy from a branch**.
   * Select branch: `main`, folder: `/ (root)`.
   * Click **Save**.

4. **Access Published PWA**:
   * GitHub will generate your HTTPS live URL (e.g. `https://<your-username>.github.io/garment-inventory-verify/`).
   * Open the link on any smartphone, tablet, or laptop browser.
   * Tap "Add to Home Screen" or "Install App" to use it as a standalone Progressive Web App!

---

## 📱 How to Use

### Step 1: Start Session & Upload Excel
1. Open the app on your mobile or laptop.
2. Enter Party / Supplier Name, Invoice Number, and Date.
3. Drag & drop or browse to select your supplier Excel sheet (`.xlsx`, `.xls`, or `.csv`).
4. Click **Upload & Parse Excel**.

### Step 2: Column Mapping
1. Verify that EAN / Barcode and Expected Quantity columns are mapped correctly.
2. Click **Auto-Suggest Mapping** or manually adjust dropdowns.
3. Click **Proceed to Setup**.

### Step 3: Verification Options Setup
1. Enable/disable desired verification fields (MRP, Size, Brand, Design #, Nature).
2. Enable audio beep and device vibration feedback.
3. Click **Start Barcode Scanning**.

### Step 4: Scan & Verify
1. Point your USB barcode scanner gun at the garment tag or click **Open Camera Scanner**.
2. Scanned item details appear immediately:
   * Click **+1 Scan Count** or rescan barcode to increment count.
   * Verify MRP (click **MRP Match** or **MRP Different** to enter tag MRP).
   * Verify Size (click **Size Match** or **Size Different** to enter tag size).
   * Enter physical quantity directly if counting in bulk.
   * If a scanned EAN is not in Excel, tap **Add Extra / Unlisted Stock Item**.

### Step 5: Review & Download Excel
1. Navigate to **Overview** to search and filter pending, verified, or mismatch items.
2. Navigate to **Export** to review final metrics.
3. Click **Download Verified Excel (.xlsx)** to download the completed inventory verification report.

---

## 📄 License
MIT License. Free for commercial and personal garment inventory management.
