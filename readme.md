<h1 align="center">🍽️ Hostel Meals – Backend Server (Express.js + MongoDB)</h1>

<p align="center">
  A complete backend API for university hostel meal & review management system.
  <br>
  Built with <strong>Express.js, MongoDB, Firebase Admin, Stripe</strong> and follows secure role-based architecture.
</p>



<hr>

<h2>🚀 Features at a Glance</h2>

<ul>
  <li>🔐 Firebase Token Verification using Admin SDK</li>
  <li>🧑‍🍳 Admin Meal Management (Add, Update, Delete)</li>
  <li>💬 Review System with Ratings & Deletion</li>
  <li>🥘 Upcoming Meals with Publish/Unpublish Controls</li>
  <li>👍 Meal Likes & Meal Request System (Role-Based)</li>
  <li>💳 Stripe Payment Integration for Premium Badge</li>
  <li>🧾 Payment History Tracking & Badge Assignment</li>
  <li>🧑‍🎓 Role-Based Access Control (User / Admin)</li>
  <li>🔎 Server-Side Search on Meals & Users</li>
  <li>📊 Pagination & Sorting Support</li>
  <li>🔐 Protected API Routes with Environment Configuration</li>
</ul>

<hr>

<h2>🛠️ Technology Stack</h2>

<table>
  <tr><td><strong>Feature</strong></td><td><strong>Tech / Tool</strong></td></tr>
  <tr><td>Server Framework</td><td>Express.js</td></tr>
  <tr><td>Database</td><td>MongoDB</td></tr>
  <tr><td>Authentication</td><td>Firebase Admin SDK</td></tr>
  <tr><td>Payment Gateway</td><td>Stripe</td></tr>
  <tr><td>Environment Config</td><td>dotenv</td></tr>
  <tr><td>Cross-Origin Requests</td><td>CORS</td></tr>
  <tr><td>Dev Monitoring</td><td>Nodemon</td></tr>
</table>

<hr>

<h2>📁 Folder Structure</h2>

```bash
Hostel-Meals-Server/
├── index.js               # Main entry point
├── convertKey.js          # Firebase private key converter
├── package.json           # Dependencies & scripts
├── vercel.json            # Vercel deployment config
├── .env                   # Environment variables
├── /routes                # All route handlers
│   ├── meals.routes.js
│   ├── reviews.routes.js
│   ├── users.routes.js
│   ├── payments.routes.js
│   └── ...
├── /controllers           # Controller functions
├── /middleware            # Auth, role, error handling
├── /models                # Mongoose models
└── /utils                 # Helper functions

```
<hr>

```bash
# Clone the repo
git clone https://github.com/JahidGittu/Hostel-Meals-Server-Side.git

# Go to the project directory
cd Hostel-Meals-Server-Side

# Install dependencies
npm install

# Start the server
npm run dev
