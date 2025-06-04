#### Fonte Lenders - Digital Loan Management System

Fonte Lenders is a modern, fully responsive digital lending platform built to streamline the loan application, management, and repayment process. The system includes a customer-facing application portal and a secure admin dashboard to manage and track loan activity efficiently.

#### Pages Overview

Page	Description	Access
index.html	Elegant landing page introducing services	Public
apply.html	Detailed loan application form	Public
repay.html	Customer repayment submission page	Customer
admin.html	Admin control panel for loan management	Admin Only
terms.html	Terms and conditions for transparency	Public

## Key Features
   # Customer-Facing Features
1. Interactive Loan Form — Applicants fill in personal, financial, and guarantor details.

2. ID Document Upload — Users can upload front and back images of their ID cards.

3. Digital Signature — Integrated Signature Pad allows applicants to e-sign.

4. Repayment Portal — Customers can submit proof of payment and repayment details online.

    # Admin Features
1. Application Management — View, sort, and review loan applications.

2. Customer Database — Access full applicant profiles and supporting documents.

3. Loan Status Tracking — Monitor loans from application to full repayment.

4. Dashboard Analytics — Visual stats and insights into lending activity.

    # Technology Stack
Frontend
HTML5, CSS3, JavaScript — Responsive, clean, and modern UI

Signature Pad.js — Capture digital signatures on the fly

FormSubmit.co — Serverless form handling for rapid prototyping

Security
✅ Client-side form validation

🛡 Honeypot technique to prevent bot submissions

🔐 Secure file handling (basic precautions implemented)

🚀 Getting Started
1. Clone the Repository
bash
Copy
Edit
git clone https://github.com/yourusername/fonte-lenders.git
cd fonte-lenders
2. Configure FormSubmit
Edit the email in your form actions for both apply.html and repay.html:

html
Copy
Edit
<form action="https://formsubmit.co/your@email.com" method="POST">
Replace with your email address to start receiving submissions.

3. Launch the Application
You can open index.html directly in any web browser.

📁 Project Structure
csharp
Copy
Edit
fonte-lenders/
├── public/
│   ├── index.html        # Landing page
│   ├── apply.html        # Loan application form
│   ├── repay.html        # Repayment submission page
│   └── terms.html        # Terms and conditions
├── admin/
│   └── admin.html        # Admin dashboard
├── assets/
│   ├── css/              # Custom stylesheets
│   ├── js/               # JavaScript scripts (form logic, validation)
│   └── img/              # Logos, icons, and images
└── README.md             # Project documentation


📄 License
This project is licensed under the MIT License.
See the LICENSE file for more information.

👤 Developer Info
Developed by: [Kevin Shimanjala]
📧 Email: [kevinshimanjala#gmail.com]
🔗 Live Demo: [https://youtube.com/shorts/ecRRPBguB3Q?si=FRTQEBl6OLvgNtAM]

