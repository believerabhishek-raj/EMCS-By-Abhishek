Open http://localhost:5000 in your browser.
​☁️ Deploying on Render
​Push index.html, script.js, server.js, package.json, and README.md to your GitHub repository.
​Create a new Web Service on Render and connect your repository.
​Use the following build settings:
​Runtime: Node
​Build Command: npm install
​Start Command: node server.js
​Add your Environment Variables in the Render dashboard:
​NODE_ENV = production
​MONGO_URI = your_mongodb_atlas_connection_string
​MASTER_OWNER_KEY = your_secret_admin_password
​Click Create Web Service.
​🛡️ Admin Control Panel Access
​Click Login / Connect on the sidebar.
​Switch to the Admin tab.
​Leave the Staff Username blank (for Master Owner) and enter your MASTER_OWNER_KEY (default: EMCS_Admin_2026).
​From the Admin Hub, you can:
​Reply to consumer inquiries in the Support Chat Desk.
​Inspect registered consumers and sanctioned loads.
​Update live website announcements, legal policies, and FAQs.
​Monitor real-time client and server exceptions in the Error List tab.
​Export a full JSON backup of the database.

​Powered By KamAbhi Tech Solutions.