/**
 * FraudShield - Application Logic
 * Integrates image upload, details forms, Gemini 2.5 Flash API, and interactive outputs.
 */

// ==========================================================================
// APPLICATION STATE
// ==========================================================================
const state = {
    apiKey: '',
    language: 'en', // Default language is English ('en', 'hi', 'te')
    imageMimeType: '',
    imageBase64: '', // Clean base64 string (no metadata header)
    previewUrl: '',
    generatedData: null, // Stores raw JSON parsed from Gemini response
    generateOnKeySave: false, // Flag to run generation once API key is provided
    detectedEmail: '', // Target email address auto-detected by Gemini
    detectedUrlEmail: '', // Target email address for URL reporter
    isBodyManuallyEdited: false, // Tracks manual edits to the generated email body
    chatHistory: [
        {
            role: 'system',
            content: "You are CyberShield AI, an expert conversational cybersecurity assistant. Help users identify online scams, phishing attempts, protect their online credentials, understand security measures (MFA, 2FA, password safety), and advise what steps to take if they clicked a malicious link, lost money, or were compromised. Keep your answers clear, professional, concise, and structured in Markdown. Always prioritize digital safety and user empowerment."
        }
    ]
};

// Default Emails for Recipients
const RECIPIENT_EMAILS = {
    cybercrime: 'report@phishing.gov',
    bank: 'fraudalert@yourbank.com',
    provider: 'abuse@domain.com',
    ftc: 'reportfraud@ftc.gov',
    custom: ''
};

// ==========================================================================
// DOM ELEMENTS
// ==========================================================================
const el = {
    // Header & API Modal
    btnApiConfig: document.getElementById('btn-api-config'),
    apiStatusDot: document.getElementById('api-status-dot'),
    apiModal: document.getElementById('api-modal'),
    btnToggleKeyVisibility: document.getElementById('btn-toggle-key-visibility'),
    inputApiKey: document.getElementById('input-api-key'),
    btnSaveApi: document.getElementById('btn-save-api'),
    btnCancelApi: document.getElementById('btn-cancel-api'),
    btnCloseModalX: document.getElementById('btn-close-modal-x'),

    // Language Selector Elements
    langModal: document.getElementById('lang-modal'),
    btnLangSelector: document.getElementById('btn-lang-selector'),
    currentLangText: document.getElementById('current-lang-text'),
    langDropdown: document.getElementById('lang-dropdown'),
    langSelectBtns: document.querySelectorAll('.lang-select-btn'),
    langOptBtns: document.querySelectorAll('.lang-opt-btn'),

    // Uploader Zone
    dropZone: document.getElementById('drop-zone'),
    fileInput: document.getElementById('file-input'),
    dropZonePrompt: document.getElementById('drop-zone-prompt'),
    dropZonePreview: document.getElementById('drop-zone-preview'),
    previewImage: document.getElementById('preview-image'),
    previewFilename: document.getElementById('preview-filename'),
    btnRemoveImage: document.getElementById('btn-remove-image'),

    // Auto-Detection Status Bar
    detectedCategoryText: document.getElementById('detected-category-text'),
    detectedRecipientText: document.getElementById('detected-recipient-text'),
    detectedEmailText: document.getElementById('detected-email-text'),

    // Output States
    outputEmptyState: document.getElementById('output-empty-state'),
    outputLoadingState: document.getElementById('output-loading-state'),
    outputLoadedState: document.getElementById('output-loaded-state'),
    
    // Loading Steps indicators
    step1: document.getElementById('step-1'),
    step2: document.getElementById('step-2'),
    step3: document.getElementById('step-3'),

    // Tabs & Outputs panels
    tabButtons: document.querySelectorAll('.tab-btn'),
    tabContents: document.querySelectorAll('.tab-content'),
    emailSubject: document.getElementById('email-subject'),
    emailBody: document.getElementById('email-body'),
    threatAnalysisContent: document.getElementById('threat-analysis-content'),
    checklistContainer: document.getElementById('checklist-items-container'),
    
    // Action Buttons
    btnCopySubject: document.getElementById('btn-copy-subject'),
    btnCopyEmail: document.getElementById('btn-copy-email'),
    btnDownloadEmail: document.getElementById('btn-download-email'),
    btnDownloadReport: document.getElementById('btn-download-report'),
    btnSendEmail: document.getElementById('btn-send-email'),
    toastContainer: document.getElementById('toast-container'),

    // Personal details inputs
    inputVictimName: document.getElementById('input-victim-name'),
    inputVictimPhone: document.getElementById('input-victim-phone'),
    inputVictimExtra: document.getElementById('input-victim-extra'),

    // Top Navigation Tabs
    navTabs: document.querySelectorAll('.nav-tab'),
    appViews: document.querySelectorAll('.app-view'),

    // Phishing Link Analyzer DOM Elements
    inputScamUrl: document.getElementById('input-scam-url'),
    btnAnalyzeUrl: document.getElementById('btn-analyze-url'),
    urlEmptyState: document.getElementById('url-empty-state'),
    urlLoadingState: document.getElementById('url-loading-state'),
    urlLoadedState: document.getElementById('url-loaded-state'),
    urlProgressCircle: document.getElementById('url-progress-circle'),
    urlScoreText: document.getElementById('url-score-text'),
    urlSafetyStatus: document.getElementById('url-safety-status'),
    urlRiskBadge: document.getElementById('url-risk-badge'),
    urlDisplayText: document.getElementById('url-display-text'),
    urlTargetBrand: document.getElementById('url-target-brand'),
    urlBrandBanner: document.getElementById('url-brand-banner'),
    urlSimpleExpl: document.getElementById('url-simple-expl'),
    urlEduExpl: document.getElementById('url-edu-expl'),
    urlDosList: document.getElementById('url-dos-list'),
    urlDontsList: document.getElementById('url-donts-list'),
    urlIndicatorsContent: document.getElementById('url-indicators-content'),
    urlActionsContainer: document.getElementById('url-actions-container'),

    // AI Security Assistant Chatbot DOM Elements
    quickQueryCards: document.querySelectorAll('.quick-query-card'),
    chatMessagesContainer: document.getElementById('chat-messages-container'),
    inputChatMessage: document.getElementById('input-chat-message'),
    btnSendChat: document.getElementById('btn-send-chat'),
    btnClearChat: document.getElementById('btn-clear-chat')
};

// ==========================================================================
// TRANSLATION SYSTEM (ENGLISH, HINDI, TELUGU)
// ==========================================================================
const translations = {
    en: {
        "logo-sub": "AI Cybercrime Assistant",
        "nav-reporter": "Evidence Reporter",
        "nav-link": "Link Analyzer",
        "nav-chatbot": "Security Assistant",
        "btn-api-text": "API Key",
        "panel-details-title": "Incident Details",
        "panel-details-desc": "Upload fraud proof and customize your complaint",
        "dropzone-title": "Upload Evidence Image",
        "dropzone-desc": "Drag and drop screenshot of fake email, SMS, or scam page here",
        "dropzone-btn": "Browse Files",
        "dropzone-limits": "Supports PNG, JPG, WEBP (Max 10MB)",
        "btn-remove": "Remove",
        "acc-title": "Personalize Report (Optional)",
        "lbl-victim-name": "Your Name",
        "lbl-victim-phone": "Your Phone",
        "lbl-victim-extra": "Additional Context (e.g. Account Number, Details)",
        "placeholder-victim-name": "John Doe",
        "placeholder-victim-phone": "+1 (555) 019-2834",
        "placeholder-victim-extra": "Chase Account Ending in 1234",
        "guide-title": "Zero-Touch AI Analysis",
        "guide-desc": "Upload a screenshot and let FraudShield handle the entire process automatically:",
        "guide-step1-title": "Evidence Scanning",
        "guide-step1-desc": "Extracts scammer email addresses, phishing links, timestamps, and spoofed logos.",
        "guide-step2-title": "Cybercrime Classification",
        "guide-step2-desc": "Identifies the crime type (e.g., Financial Phishing, Smishing, Identity Spoofing).",
        "guide-step3-title": "Target Matching",
        "guide-step3-desc": "Determines the correct abuse desks, watchdogs, or portals for reporting.",
        "empty-title": "Ready to Analyze",
        "empty-desc": "Upload a screenshot of the scam or fraud on the left panel. FraudShield will immediately classify the cybercrime, locate the reporting authority, and draft your complaint.",
        "empty-feat1": "Threat Indicator Scan",
        "empty-feat2": "Polished Complaint Letter",
        "empty-feat3": "Instant Action Steps",
        "loading-title": "Analyzing Evidence",
        "loading-desc": "AI is scanning the image files and crafting your response...",
        "loading-step1": "Reading visual evidence & text...",
        "loading-step2": "Identifying cybersecurity indicators...",
        "loading-step3": "Drafting formal complaint & checklist...",
        "badge-class": "Cybercrime Classification",
        "badge-auth": "Target Authority",
        "badge-dest": "Reporting Destination",
        "status-analyzing": "Analyzing...",
        "tab-btn-email": "Complaint Email",
        "tab-btn-threats": "Threat Analysis",
        "tab-btn-checklist": "Next Steps",
        "lbl-subject": "Email Subject",
        "lbl-body": "Email Body (Editable)",
        "btn-copy": "Copy Entire Email",
        "btn-download": "Save as Text",
        "btn-send": "Send Email",
        "threat-banner-title": "AI Analysis Report",
        "threat-banner-desc": "Key evidence elements and cybersecurity red flags extracted from the image.",
        "btn-save-report": "Save Report",
        "checklist-title-header": "Cyber Safety Action Items",
        "checklist-subtitle-header": "Complete these steps immediately to safeguard your account and digital presence.",
        "checklist-disclaimer": "Disclaimer: These suggestions are based on standard security practices. Please contact your organization's IT department or bank support directly for definitive instructions.",
        "link-title": "Link Scanner",
        "link-desc": "Verify suspicious URLs for phishing indicators and fraud campaigns",
        "lbl-scam-url": "Suspicious URL / Link",
        "placeholder-scam-url": "Paste link here (e.g., http://login-netflix-verify.net/auth)",
        "btn-run-scan": "Run Threat Scan",
        "link-guide-title": "How URL Scanning Works",
        "link-guide-desc": "The system performs a structural check on the domain and path, assessing:",
        "link-guide-feat1-title": "Typosquatting & Lookalikes",
        "link-guide-feat1-desc": "Scans for character substitutions (like 'rn' for 'm') and brand names mixed with generic words.",
        "link-guide-feat2-title": "TLD Domain Risk",
        "link-guide-feat2-desc": "Assesses the safety reputation of the top-level domain extensions (.xyz, .top, .info vs .com).",
        "link-guide-feat3-title": "Protocol Safety",
        "link-guide-feat3-desc": "Checks if the link relies on insecure HTTP protocols which lack data encryption.",
        "url-empty-title": "Threat Scan Ready",
        "url-empty-desc": "Paste a suspicious link on the left panel and click \"Run Threat Scan\" to extract registrar details, brand spoofing scores, and risk evaluations.",
        "url-loading-title": "Scanning Link",
        "url-loading-desc": "Running structural audit and security classification on the domain...",
        "url-score-title": "Domain Safety Score",
        "lbl-analyzed-link": "Analyzed Link:",
        "lbl-impersonate-prefix": "Target Brand Impersonated:",
        "url-impersonate-desc": "This page mimics a secure portal to harvest credentials for this service.",
        "url-simple-expl-title": "What is this link? (Simplified)",
        "url-edu-title": "Link Structure Explained",
        "url-dos-title": "Actions to Take",
        "url-donts-title": "Things to Avoid",
        "url-tech-title": "Technical Risk Indicators",
        "url-recs-title": "Recommended Actions",
        "chat-guide-title": "Quick Questions",
        "chat-guide-desc": "Select any common cyber safety concern to get instant guidance",
        "query1-title": "Spot Fake Emails",
        "query1-desc": "Learn to detect sender name spoofing and character substitutions.",
        "query2-title": "Clicked a Link",
        "query2-desc": "Immediate actions to take for safety if you accidentally loaded a scam page.",
        "query3-title": "Enable MFA",
        "query3-desc": "Understand how 2FA works and why it stops credential harvesting.",
        "query4-title": "OTP Scams",
        "query4-desc": "How one-time passcode verification is exploited by banking scammers.",
        "chat-title": "Chat Assistant",
        "chat-desc": "Ask CyberShield AI about security guidelines, threats, or protection tips",
        "btn-clear-chat-text": "Clear Chat",
        "placeholder-chat-msg": "Ask about phishing, MFA, secure passwords, or report steps...",
        "chat-welcome": "Hello! I am <strong>CyberShield AI</strong>, your security assistant. I can answer questions about digital safety, phishing indicators, securing your online accounts, or what to do if you suspect a scam. How can I help you today?",
        "api-modal-title": "Groq API Settings",
        "api-modal-desc": "This application processes image uploads and writes custom emails locally in your browser using Groq Llama 4 Scout vision model. A Groq console API key is required to perform analysis.",
        "api-modal-info-title": "How to get an API Key?",
        "api-modal-info-desc": "Go to Groq Console, sign in with your account, and click Create API Key.",
        "lbl-api-key": "Groq API Key",
        "placeholder-api-key": "gsk_...",
        "api-modal-help": "Your API key is stored safely on your machine in localStorage. It is never uploaded to any server.",
        "btn-cancel": "Cancel",
        "btn-save-api": "Save API Key"
    },
    hi: {
        "logo-sub": "एआई साइबर अपराध सहायक",
        "nav-reporter": "शिकायत रिपोर्टर",
        "nav-link": "लिंक विश्लेषक",
        "nav-chatbot": "सुरक्षा सहायक",
        "btn-api-text": "एपीआई कुंजी",
        "panel-details-title": "घटना का विवरण",
        "panel-details-desc": "धोखाधड़ी का प्रमाण अपलोड करें और शिकायत कस्टमाइज़ करें",
        "dropzone-title": "साक्ष्य छवि अपलोड करें",
        "dropzone-desc": "नकली ईमेल, एसएमएस या घोटाले वाले पेज का स्क्रीनशॉट यहां खींचें और छोड़ें",
        "dropzone-btn": "फ़ाइलें ब्राउज़ करें",
        "dropzone-limits": "PNG, JPG, WEBP का समर्थन करता है (अधिकतम 10MB)",
        "btn-remove": "हटाएं",
        "acc-title": "रिपोर्ट को कस्टमाइज़ करें (वैकल्पिक)",
        "lbl-victim-name": "आपका नाम",
        "lbl-victim-phone": "आपका फोन नंबर",
        "lbl-victim-extra": "अतिरिक्त संदर्भ (जैसे खाता संख्या, विवरण)",
        "placeholder-victim-name": "राम प्रसाद",
        "placeholder-victim-phone": "+91 98765 43210",
        "placeholder-victim-extra": "एसबीआई खाता संख्या 1234 पर समाप्त होने वाला",
        "guide-title": "जीरो-टच एआई विश्लेषण",
        "guide-desc": "स्क्रीनशॉट अपलोड करें और फ्रॉडशील्ड को पूरी प्रक्रिया स्वचालित रूप से संभालने दें:",
        "guide-step1-title": "साक्ष्य स्कैनिंग",
        "guide-step1-desc": "प्रेषक के ईमेल पते, फ़िशिंग लिंक, टाइमस्टैम्प और नकली लोगो को निकालता है।",
        "guide-step2-title": "साइबर अपराध वर्गीकरण",
        "guide-step2-desc": "अपराध के प्रकार की पहचान करता है (जैसे, वित्तीय फ़िशिंग, स्मिशिंग, पहचान की नकल)।",
        "guide-step3-title": "लक्षित मिलान",
        "guide-step3-desc": "रिपोर्टिंग के लिए सही दुरुपयोग डेस्क, प्रहरी या पोर्टल निर्धारित करता है।",
        "empty-title": "विश्लेषण के लिए तैयार",
        "empty-desc": "बाएं पैनल पर घोटाले या धोखाधड़ी का स्क्रीनशॉट अपलोड करें। फ्रॉडशील्ड तुरंत साइबर अपराध को वर्गीकृत करेगा, रिपोर्टिंग प्राधिकरण का पता लगाएगा, और आपकी शिकायत का मसौदा तैयार करेगा।",
        "empty-feat1": "खतरा संकेतक स्कैन",
        "empty-feat2": "तैयार शिकायत पत्र",
        "empty-feat3": "तत्काल कार्रवाई कदम",
        "loading-title": "साक्ष्यों का विश्लेषण किया जा रहा है",
        "loading-desc": "एआई छवि फ़ाइलों को स्कैन कर रहा है और आपकी प्रतिक्रिया तैयार कर रहा है...",
        "loading-step1": "दृश्य साक्ष्य और पाठ पढ़ना...",
        "loading-step2": "साइबर सुरक्षा संकेतकों की पहचान करना...",
        "loading-step3": "औपचारिक शिकायत और चेकलिस्ट का मसौदा तैयार करना...",
        "badge-class": "साइबर अपराध वर्गीकरण",
        "badge-auth": "लक्षित प्राधिकरण",
        "badge-dest": "रिपोर्टिंग गंतव्य",
        "status-analyzing": "विश्लेषण कर रहा है...",
        "tab-btn-email": "शिकायत ईमेल",
        "tab-btn-threats": "खतरे का विश्लेषण",
        "tab-btn-checklist": "अगले कदम",
        "lbl-subject": "ईमेल का विषय",
        "lbl-body": "ईमेल बॉडी (संपादन योग्य)",
        "btn-copy": "संपूर्ण ईमेल कॉपी करें",
        "btn-download": "टेक्स्ट के रूप में सहेजें",
        "btn-send": "ईमेल भेजें",
        "threat-banner-title": "एआई विश्लेषण रिपोर्ट",
        "threat-banner-desc": "छवि से निकाले गए मुख्य साक्ष्य तत्व और साइबर सुरक्षा खतरे के संकेत।",
        "btn-save-report": "रिपोर्ट सहेजें",
        "checklist-title-header": "साइबर सुरक्षा कार्रवाई आइटम",
        "checklist-subtitle-header": "अपने खाते और डिजिटल उपस्थिति की सुरक्षा के लिए इन चरणों को तुरंत पूरा करें।",
        "checklist-disclaimer": "अस्वीकरण: ये सुझाव मानक सुरक्षा प्रथाओं पर आधारित हैं। निश्चित निर्देशों के लिए कृपया अपने संगठन के आईटी विभाग या बैंक सहायता से सीधे संपर्क करें।",
        "link-title": "लिंक स्कैनर",
        "link-desc": "फ़िशिंग संकेतकों और धोखाधड़ी अभियानों के लिए संदिग्ध यूआरएल सत्यापित करें",
        "lbl-scam-url": "संदिग्ध यूआरएल / लिंक",
        "placeholder-scam-url": "लिंक यहाँ पेस्ट करें (जैसे, http://login-netflix-verify.net/auth)",
        "btn-run-scan": "खतरा स्कैन चलाएं",
        "link-guide-title": "यूआरएल स्कैनिंग कैसे काम करती है",
        "link-guide-desc": "सिस्टम डोमेन और पथ की संरचनात्मक जांच करता है, और मूल्यांकन करता है:",
        "link-guide-feat1-title": "टाइपोस्पोटिंग और एक जैसे दिखने वाले",
        "link-guide-feat1-desc": "वर्ण प्रतिस्थापन (जैसे 'm' के लिए 'rn') और सामान्य शब्दों के साथ मिश्रित ब्रांड नामों के लिए स्कैन करता है।",
        "link-guide-feat2-title": "टीएलडी डोमेन जोखिम",
        "link-guide-feat2-desc": "टॉप-लेवल डोमेन एक्सटेंशन (.xyz, .top, .info बनाम .com) की सुरक्षा प्रतिष्ठा का आकलन करता है।",
        "link-guide-feat3-title": "प्रोटोकॉल सुरक्षा",
        "link-guide-feat3-desc": "जांच करता है कि क्या लिंक असुरक्षित HTTP प्रोटोकॉल पर निर्भर है जिसमें डेटा एन्क्रिप्शन की कमी होती है।",
        "url-empty-title": "खतरा स्कैन तैयार",
        "url-empty-desc": "बाएं पैनल पर एक संदिग्ध लिंक पेस्ट करें और रजिस्ट्रार विवरण, ब्रांड स्पूफिंग स्कोर और जोखिम मूल्यांकन निकालने के लिए \"खतरा स्कैन चलाएं\" पर क्लिक करें।",
        "url-loading-title": "लिंक स्कैन किया जा रहा है",
        "url-loading-desc": "डोमेन पर संरचनात्मक ऑडिट और सुरक्षा वर्गीकरण चलाया जा रहा है...",
        "url-score-title": "डोमेन सुरक्षा स्कोर",
        "lbl-analyzed-link": "विश्लेषण किया गया लिंक:",
        "lbl-impersonate-prefix": "नकल किया गया लक्षित ब्रांड:",
        "url-impersonate-desc": "यह पृष्ठ इस सेवा के लिए क्रेडेंशियल एकत्र करने के लिए एक सुरक्षित पोर्टल की नकल करता है।",
        "url-simple-expl-title": "यह लिंक क्या है? (सरलीकृत)",
        "url-edu-title": "लिंक संरचना की व्याख्या",
        "url-dos-title": "कदम उठाने योग्य",
        "url-donts-title": "परहेज करने योग्य बातें",
        "url-tech-title": "तकनीकी जोखिम संकेतक",
        "url-recs-title": "अनुशंसित कार्रवाई",
        "chat-guide-title": "त्वरित प्रश्न",
        "chat-guide-desc": "त्वरित मार्गदर्शन प्राप्त करने के लिए किसी भी सामान्य साइबर सुरक्षा चिंता का चयन करें",
        "query1-title": "नकली ईमेल पहचानें",
        "query1-desc": "प्रेषक के नाम की नकल और अक्षरों के प्रतिस्थापन का पता लगाना सीखें।",
        "query2-title": "लिंक पर क्लिक किया",
        "query2-desc": "यदि आपने गलती से कोई घोटाला पृष्ठ लोड कर लिया है तो सुरक्षा के लिए की जाने वाली तत्काल कार्रवाई।",
        "query3-title": "एमएफए सक्षम करें",
        "query3-desc": "समझें कि 2एफए कैसे काम करता है और यह क्रेडेंशियल चोरी को क्यों रोकता है।",
        "query4-title": "ओटीपी घोटाले",
        "query4-desc": "बैंकिंग स्कैमर्स द्वारा वन-टाइम पासकोड सत्यापन का शोषण कैसे किया जाता है।",
        "chat-title": "चैट सहायक",
        "chat-desc": "साइबरशील्ड एआई से सुरक्षा दिशानिर्देशों, खतरों या सुरक्षा युक्तियों के बारे में पूछें",
        "btn-clear-chat-text": "चैट साफ करें",
        "placeholder-chat-msg": "फ़िशिंग, एमएफए, सुरक्षित पासवर्ड या रिपोर्ट चरणों के बारे में पूछें...",
        "chat-welcome": "नमस्ते! मैं <strong>साइबरशील्ड एआई</strong> हूं, आपका सुरक्षा सहायक। मैं डिजिटल सुरक्षा, फ़िशिंग संकेतकों, आपके ऑनलाइन खातों को सुरक्षित करने, या यदि आपको किसी घोटाले का संदेह है तो क्या करना चाहिए, इसके बारे में प्रश्नों के उत्तर दे सकता हूं। आज मैं आपकी क्या सहायता कर सकता हूँ?",
        "api-modal-title": "Groq एपीआई सेटिंग्स",
        "api-modal-desc": "यह एप्लिकेशन ग्रोत लामा 4 स्काउट विज़न मॉडल का उपयोग करके आपके ब्राउज़र में स्थानीय रूप से छवि अपलोड और कस्टम ईमेल लिखता है। विश्लेषण करने के लिए एक Groq कंसोल एपीआई कुंजी आवश्यक है।",
        "api-modal-info-title": "एपीआई कुंजी कैसे प्राप्त करें?",
        "api-modal-info-desc": "Groq कंसोल पर जाएं, अपने खाते से साइन इन करें, और एपीआई कुंजी बनाएं पर क्लिक करें।",
        "lbl-api-key": "Groq एपीआई कुंजी",
        "placeholder-api-key": "gsk_...",
        "api-modal-help": "आपकी एपीआई कुंजी आपके मशीन पर localStorage में सुरक्षित रूप से संग्रहीत है। इसे कभी भी किसी सर्वर पर अपलोड नहीं किया जाता है।",
        "btn-cancel": "रद्द करें",
        "btn-save-api": "एपीआई कुंजी सहेजें"
    },
    te: {
        "logo-sub": "AI సైబర్ క్రైమ్ సహాయకుడు",
        "nav-reporter": "సాక్ష్యాల నివేదిక",
        "nav-link": "లింక్ విశ్లేషణ",
        "nav-chatbot": "భద్రతా సహాయకుడు",
        "btn-api-text": "API కీ",
        "panel-details-title": "ఘటన వివరాలు",
        "panel-details-desc": "మోసం రుజువును అప్‌లోడ్ చేయండి మరియు మీ ఫిర్యాదును అనుకూలీకరించండి",
        "dropzone-title": "సాక్ష్యాల చిత్రాన్ని అప్‌లోడ్ చేయండి",
        "dropzone-desc": "నకిలీ ఇమెయిల్, SMS లేదా స్కామ్ పేజీ స్క్రీన్‌షాట్‌ను ఇక్కడ లాగి వదలండి",
        "dropzone-btn": "ఫైల్‌లను బ్రౌజ్ చేయి",
        "dropzone-limits": "PNG, JPG, WEBP సపోర్ట్ చేస్తుంది (గరిష్టంగా 10MB)",
        "btn-remove": "తొలగించు",
        "acc-title": "నివేదికను వ్యక్తిగతీకరించండి (ఐచ్ఛికం)",
        "lbl-victim-name": "మీ పేరు",
        "lbl-victim-phone": "మీ ఫోన్",
        "lbl-victim-extra": "అదనపు సందర్భం (ఉదా. ఖాతా సంఖ్య, వివరాలు)",
        "placeholder-victim-name": "రామారావు",
        "placeholder-victim-phone": "+91 98765 43210",
        "placeholder-victim-extra": "SBI ఖాతా సంఖ్య 1234 తో ముగిసేది",
        "guide-title": "జీరో-టచ్ AI విశ్లేషణ",
        "guide-desc": "ఒక స్క్రీన్‌షాట్‌ను అప్‌లోడ్ చేయండి మరియు ఫ్రాడ్‌షీల్డ్ ఆ ప్రక్రియను ఆటోమేటిక్‌గా నిర్వహించనివ్వండి:",
        "guide-step1-title": "సాక్ష్యాల స్కానింగ్",
        "guide-step1-desc": "స్కామర్ ఇమెయిల్ చిరునామాలు, ఫిషింగ్ లింకులు, టైమ్‌స్టాంప్‌లు మరియు నకిలీ లోగోలను సేకరిస్తుంది.",
        "guide-step2-title": "సైబర్ క్రైమ్ వర్గీకరణ",
        "guide-step2-desc": "నేర రకాన్ని గుర్తిస్తుంది (ఉదా., ఆర్థిక ఫిషింగ్, స్మిషింగ్, గుర్తింపు స్పూఫింగ్).",
        "guide-step3-title": "టార్గెట్ మ్యాచింగ్",
        "guide-step3-desc": "ఫిర్యాదు చేయడానికి సరైన అబ్యూజ్ డెస్క్‌లు, వాచ్‌డాగ్‌లు లేదా పోర్టల్‌లను నిర్ణయిస్తుంది.",
        "empty-title": "విశ్లేషణకు సిద్ధంగా ఉంది",
        "empty-desc": "ఎడమ ప్యానెల్‌లో స్కామ్ లేదా మోసం యొక్క స్క్రీన్‌షాట్‌ను అప్‌లోడ్ చేయండి. ఫ్రాడ్‌షీల్డ్ వెంటనే సైబర్ క్రైమ్‌ను వర్గీకరిస్తుంది, నివేదించాల్సిన అధికారాన్ని కనుగొంటుంది మరియు మీ ఫిర్యాదును సిద్ధం చేస్తుంది.",
        "empty-feat1": "థ్రెట్ ఇండికేటర్ స్కాన్",
        "empty-feat2": "అద్భుతమైన ఫిర్యాదు లేఖ",
        "empty-feat3": "తక్షణ చర్యల జాబితా",
        "loading-title": "సాక్ష్యాలను విశ్లేషిస్తోంది",
        "loading-desc": "AI ఇమేజ్ ఫైళ్లను స్కాన్ చేస్తోంది మరియు మీ ప్రతిస్పందనను రూపొందిస్తోంది...",
        "loading-step1": "విజువల్ సాక్ష్యాలు & వచనాన్ని చదువుతోంది...",
        "loading-step2": "సైబర్ సెక్యూరిటీ సూచికలను గుర్తిస్తోంది...",
        "loading-step3": "औपचारिक ఫిర్యాదు & చెక్‌లిస్ట్‌ను సిద్ధం చేస్తోంది...",
        "badge-class": "సైబర్ క్రైమ్ వర్గీకరణ",
        "badge-auth": "లక్ష్య అధికారం",
        "badge-dest": "రిపోర్టింగ్ గమ్యస్థానం",
        "status-analyzing": "విశ్లేషిస్తోంది...",
        "tab-btn-email": "ఫిర్యాదు ఇమెయిల్",
        "tab-btn-threats": "థ్రెట్ విశ్లేషణ",
        "tab-btn-checklist": "తదుపరి చర్యలు",
        "lbl-subject": "ఇమెయిల్ సబ్జెక్ట్",
        "lbl-body": "ఇమెయిల్ బాడీ (ఎడిట్ చేయవచ్చు)",
        "btn-copy": "మొత్తం ఇమెయిల్‌ను కాపీ చేయి",
        "btn-download": "టెక్స్ట్‌గా సేవ్ చేయి",
        "btn-send": "ఇమెయిల్ పంపు",
        "threat-banner-title": "AI విశ్లేషణ నివేదిక",
        "threat-banner-desc": "చిత్రం నుండి సంగ్రహించిన కీలక ఆధారాలు మరియు సైబర్ సెక్యూరిటీ హెచ్చరికలు.",
        "btn-save-report": "రిపోర్ట్ సేవ్ చేయి",
        "checklist-title-header": "సైబర్ సేఫ్టీ యాక్షన్ ఐటెమ్స్",
        "checklist-subtitle-header": "మీ ఖాతా మరియు డిజిటల్ భద్రతను కాపాడటానికి ఈ తదుపరి చర్యలను వెంటనే పూర్తి చేయండి.",
        "checklist-disclaimer": "నిరాకరణ: ఈ సూచనలు ప్రామాణిక భద్రతా పద్ధతులపై ఆధారపడి ఉంటాయి. ఖచ్చితమైన సూచనల కోసం దయచేసి మీ సంస్థ యొక్క IT విభాగం లేదా బ్యాంక్ మద్దతును నేరుగా సంప్రదించండి.",
        "link-title": "లింక్ స్కానర్",
        "link-desc": "ఫిషింగ్ సూచికలు మరియు మోసాల కోసం అనుమానాస్పద URLలను ధృవీకరించండి",
        "lbl-scam-url": "అనుమానాస్పద URL / లింక్",
        "placeholder-scam-url": "లింక్‌ను ఇక్కడ పేస్ట్ చేయండి (ఉదా. http://login-netflix-verify.net/auth)",
        "btn-run-scan": "థ్రెట్ స్కాన్ రన్ చేయి",
        "link-guide-title": "URL స్కానింగ్ ఎలా పనిచేస్తుంది",
        "link-guide-desc": "సిస్టమ్ డొమైన్ మరియు పాత్ యొక్క నిర్మాణ తనిఖీని నిర్వహిస్తుంది, వీటిని అంచనా వేస్తుంది:",
        "link-guide-feat1-title": "టైపోస్క్వాటింగ్ & ఒకేలా ఉండేవి",
        "link-guide-feat1-desc": "అక్షర ప్రత్యామ్నాయాలు (ఉదా. 'm' కోసం 'rn') మరియు బ్రాండ్ పేర్లు సాధారణ పదాలతో కలిపి ఉన్న వాటి కోసం స్కాన్ చేస్తుంది.",
        "link-guide-feat2-title": "TLD డొమైన్ రిస్క్",
        "link-guide-feat2-desc": "టాప్-లెవల్ డొమైన్ పొడిగింపుల (.xyz, .top, .info vs .com) యొక్క భద్రతా కీర్తిని అంచనా వేస్తుంది.",
        "link-guide-feat3-title": "ప్రోటోకాల్ భద్రత",
        "link-guide-feat3-desc": "లింక్ డేటా ఎన్‌క్రిప్షన్ లేని అసురక్షిత HTTP ప్రోటోకాల్‌లపై ఆధారపడి ఉందో లేదో తనిఖీ చేస్తుంది.",
        "url-empty-title": "థ్రెట్ స్కాన్ సిద్ధంగా ఉంది",
        "url-empty-desc": "ఎడమ ప్యానెల్‌లో అనుమానాస్పద లింక్‌ను పేస్ట్ చేసి, రిజిస్ట్రార్ వివరాలు, బ్రాండ్ స్పూఫింగ్ స్కోర్లు మరియు రిస్క్ మూల్యాంకనాలను సేకరించడానికి \"థ్రెట్ స్కాన్ రన్ చేయి\" క్లిక్ చేయండి.",
        "url-loading-title": "లింక్‌ను స్కాన్ చేస్తోంది",
        "url-loading-desc": "డొమైన్‌పై నిర్మాణ ఆడిట్ మరియు భద్రతా వర్గీకరణను రన్ చేస్తోంది...",
        "url-score-title": "డొమైన్ భద్రతా స్కోరు",
        "lbl-analyzed-link": "విశ్లేషించబడిన లింక్:",
        "lbl-impersonate-prefix": "నకిలీ చేయబడిన లక్ష్య బ్రాండ్:",
        "url-impersonate-desc": "ఈ పేజీ ఈ సేవ యొక్క లాగిన్ వివరాలను దొంగిలించడానికి ఒక సురక్షితమైన పోర్టల్‌ను అనుకరిస్తుంది.",
        "url-simple-expl-title": "ఈ లింక్ ఏమిటి? (సరళీకృతం)",
        "url-edu-title": "లింక్ నిర్మాణం వివరించబడింది",
        "url-dos-title": "తీసుకోవలసిన చర్యలు",
        "url-donts-title": "నివారించాల్సిన విషయాలు",
        "url-tech-title": "సాంకేతిక రిస్క్ సూచికలు",
        "url-recs-title": "సిఫార్సు చేయబడిన చర్యలు",
        "chat-guide-title": "త్వరిత ప్రశ్నలు",
        "chat-guide-desc": "తక్షణ మార్గదర్శకత్వం పొందడానికి ఏదైనా సాధారణ సైబర్ భద్రతా సమస్యను ఎంచుకోండి",
        "query1-title": "నకిలీ ఇమెయిల్‌లను గుర్తించండి",
        "query1-desc": "పంపినవారి పేరు స్పూఫింగ్ మరియు అక్షరాల ప్రత్యామ్నాయాలను గుర్తించడం నేర్చుకోండి.",
        "query2-title": "లింక్‌పై క్లిక్ చేసారు",
        "query2-desc": "మీరు ప్రమాదవశాత్తు స్కామ్ పేజీని లోడ్ చేసినట్లయితే భద్రత కోసం తీసుకోవలసిన తక్షణ చర్యలు.",
        "query3-title": "MFA ని ప్రారంభించండి",
        "query3-desc": "2FA ఎలా పనిచేస్తుందో మరియు అది క్రెడెన్షియల్ దొంగతనాన్ని ఎందుకు ఆపుతుందో అర్థం చేసుకోండి.",
        "query4-title": "OTP స్కామ్‌లు",
        "query4-desc": "బ్యాంకింగ్ స్కామర్ల ద్వారా వన్-టైమ్ పాస్‌కోడ్ వెరిఫికేషన్ ఎలా దుర్వినియోగం చేయబడుతుందో తెలుసుకోండి.",
        "chat-title": "చాట్ సహాయకుడు",
        "chat-desc": "సైబర్ భద్రతా మార్గదర్శకాలు, బెదిరింపులు లేదా రక్షణ చిట్కాల గురించి సైబర్‌షీల్డ్ AI ని అడగండి",
        "btn-clear-chat-text": "చాట్ క్లియర్ చేయి",
        "placeholder-chat-msg": "ఫిషింగ్, MFA, సురక్షిత పాస్‌వర్డ్‌లు లేదా రిపోర్ట్ దశల గురించి అడగండి...",
        "chat-welcome": "నమస్కారం! నేను <strong>సైబర్‌షీల్డ్ AI</strong>, మీ భద్రతా సహాయకుడిని. డిజిటల్ భద్రత, ఫిషింగ్ సూచికలు, మీ ఆన్‌లైన్ ఖాతాలను సురక్షితం చేయడం లేదా మీకు ఏదైనా స్కామ్ అని అనుమానం వస్తే ఏమి చేయాలి అనే ప్రశ్నలకు నేను సమాధానం ఇవ్వగలను. ఈ రోజు నేను మీకు ఎలా సహాయపడగలను?",
        "api-modal-title": "Groq API సెట్టింగ్‌లు",
        "api-modal-desc": "ఈ అప్లికేషన్ Groq Llama 4 Scout విజన్ మోడల్‌ని ఉపయోగించి మీ బ్రౌజర్‌లో ఇమేజ్ అప్‌లోడ్‌లను ప్రాసెస్ చేస్తుంది మరియు అనుకూల ఇమెయిల్‌లను వ్రాస్తుంది. విశ్లేషణ చేయడానికి ఒక Groq కన్సోల్ API కీ అవసరం.",
        "api-modal-info-title": "API కీని పొందడం ఎలా?",
        "api-modal-info-desc": "Groq కన్సోల్‌కు వెళ్లండి, మీ ఖాతాతో సైన్ ఇన్ చేయండి మరియు Create API Key క్లిక్ చేయండి.",
        "lbl-api-key": "Groq API కీ",
        "placeholder-api-key": "gsk_...",
        "api-modal-help": "మీ API కీ మీ పరికరంలోని localStorage లో సురక్షితంగా నిల్వ చేయబడుతుంది. ఇది ఏ సర్వర్‌కు అప్‌లోడ్ చేయబడదు.",
        "btn-cancel": "రద్దు చేయి",
        "btn-save-api": "API కీని సేవ్ చేయి"
    }
};

function getSystemPrompt(lang) {
    const langName = lang === 'hi' ? 'Hindi' : (lang === 'te' ? 'Telugu' : 'English');
    return `You are CyberShield AI, an expert conversational cybersecurity assistant. Help users identify online scams, phishing attempts, protect their online credentials, understand security measures (MFA, 2FA, password safety), and advise what steps to take if they clicked a malicious link, lost money, or were compromised. Keep your answers clear, professional, concise, and structured in Markdown. Always prioritize digital safety and user empowerment. IMPORTANT: You MUST converse and answer all queries in the following language: ${langName}.`;
}

function applyLanguage(lang) {
    state.language = lang;
    localStorage.setItem('fraudshield_lang', lang);
    
    // Update button text in header
    const langNames = {
        en: 'English',
        hi: 'हिंदी (Hindi)',
        te: 'తెలుగు (Telugu)'
    };
    if (el.currentLangText) {
        el.currentLangText.textContent = langNames[lang] || 'English';
    }

    // Apply translations to data-i18n elements
    const elements = document.querySelectorAll('[data-i18n]');
    elements.forEach(elem => {
        const key = elem.getAttribute('data-i18n');
        if (translations[lang] && translations[lang][key] !== undefined) {
            const icon = elem.querySelector('i');
            if (icon) {
                elem.innerHTML = '';
                elem.appendChild(icon);
                elem.appendChild(document.createTextNode(' ' + translations[lang][key]));
            } else {
                elem.textContent = translations[lang][key];
            }
        }
    });

    // Apply translations to placeholders
    const inputs = document.querySelectorAll('[data-i18n-placeholder]');
    inputs.forEach(input => {
        const key = input.getAttribute('data-i18n-placeholder');
        if (translations[lang] && translations[lang][key] !== undefined) {
            input.setAttribute('placeholder', translations[lang][key]);
        }
    });

    // Update active class in dropdown options
    if (el.langOptBtns) {
        el.langOptBtns.forEach(btn => {
            if (btn.getAttribute('data-lang') === lang) {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
        });
    }

    // Update active class in modal select buttons
    if (el.langSelectBtns) {
        el.langSelectBtns.forEach(btn => {
            if (btn.getAttribute('data-lang') === lang) {
                btn.className = 'btn btn-accent lang-select-btn';
            } else {
                btn.className = 'btn btn-secondary lang-select-btn';
            }
        });
    }

    // Translate Chat Welcome message
    const welcomeText = translations[lang]['chat-welcome'];
    const welcomeMessageBubble = document.querySelector('#chat-messages-container .message-assistant p[data-i18n="chat-welcome"]');
    if (welcomeMessageBubble) {
        welcomeMessageBubble.innerHTML = welcomeText;
    }

    // Update Chatbot system prompt language directive dynamically
    if (state.chatHistory && state.chatHistory[0]) {
        state.chatHistory[0].content = getSystemPrompt(lang);
    }
}

function initLanguage() {
    // Register event listener for language selector click trigger
    if (el.btnLangSelector) {
        el.btnLangSelector.addEventListener('click', (e) => {
            e.stopPropagation();
            el.langDropdown.classList.toggle('hidden');
        });
    }

    // Click anywhere else to close language dropdown
    document.addEventListener('click', () => {
        if (el.langDropdown) {
            el.langDropdown.classList.add('hidden');
        }
    });

    // Switch language from header options dropdown
    if (el.langOptBtns) {
        el.langOptBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const lang = btn.getAttribute('data-lang');
                applyLanguage(lang);
                el.langDropdown.classList.add('hidden');
                showToast(`Language switched to ${lang === 'hi' ? 'Hindi' : (lang === 'te' ? 'Telugu' : 'English')}`, 'info');
            });
        });
    }

    // Modal select button events
    if (el.langSelectBtns) {
        el.langSelectBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const lang = btn.getAttribute('data-lang');
                applyLanguage(lang);
                el.langModal.classList.add('hidden');
                showToast(`Welcome! Language set to ${lang === 'hi' ? 'Hindi' : (lang === 'te' ? 'Telugu' : 'English')}`, 'success');
            });
        });
    }

    // Check localStorage
    const savedLang = localStorage.getItem('fraudshield_lang');
    if (savedLang) {
        applyLanguage(savedLang);
        el.langModal.classList.add('hidden');
    } else {
        // Show startup select modal
        el.langModal.classList.remove('hidden');
    }
}

// ==========================================================================
// TOAST NOTIFICATIONS
// ==========================================================================
function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    let iconClass = 'fa-circle-check';
    if (type === 'error') iconClass = 'fa-triangle-exclamation';
    if (type === 'info') iconClass = 'fa-circle-info';
    
    toast.innerHTML = `
        <i class="fa-solid ${iconClass}"></i>
        <span class="toast-text" style="flex: 1;">${message}</span>
        <button class="toast-close" aria-label="Dismiss Notification">
            <i class="fa-solid fa-xmark"></i>
        </button>
    `;
    
    el.toastContainer.appendChild(toast);
    
    let isDismissed = false;
    const dismissToast = () => {
        if (isDismissed) return;
        isDismissed = true;
        toast.classList.add('dismissed');
        toast.style.animation = 'fadeOut var(--transition-normal) forwards';
        toast.addEventListener('animationend', () => {
            toast.remove();
            updateClearAllButton();
        });
    };
    
    // Auto-remove toast after 4.5 seconds
    const timeoutId = setTimeout(dismissToast, 4500);
    
    // Close button click listener
    const closeBtn = toast.querySelector('.toast-close');
    closeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        clearTimeout(timeoutId);
        dismissToast();
    });

    // Clicking toast body also dismisses it
    toast.addEventListener('click', () => {
        clearTimeout(timeoutId);
        dismissToast();
    });

    updateClearAllButton();
}

// Helper to update the "Clear All" button visibility and position
function updateClearAllButton() {
    let clearBtn = el.toastContainer.querySelector('.toast-clear-all');
    const toasts = el.toastContainer.querySelectorAll('.toast:not(.dismissed)');
    
    if (toasts.length >= 2) {
        if (!clearBtn) {
            clearBtn = document.createElement('button');
            clearBtn.className = 'toast-clear-all';
            clearBtn.innerHTML = '<i class="fa-solid fa-trash-can"></i> Clear All';
            clearBtn.addEventListener('click', () => {
                const activeToasts = el.toastContainer.querySelectorAll('.toast:not(.dismissed)');
                activeToasts.forEach(t => {
                    t.style.animation = 'fadeOut var(--transition-normal) forwards';
                    t.addEventListener('animationend', () => {
                        t.remove();
                        updateClearAllButton();
                    });
                });
            });
            el.toastContainer.appendChild(clearBtn);
        } else {
            // Ensure the button remains at the end of the container
            el.toastContainer.appendChild(clearBtn);
        }
    } else {
        if (clearBtn) {
            clearBtn.remove();
        }
    }
}

// ==========================================================================
// API KEY CONFIGURATION (LOCAL STORAGE)
// ==========================================================================
const DEFAULT_API_KEY = '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';

function loadApiKey() {
    let savedKey = localStorage.getItem('fraudshield_api_key');
    // Force override if the saved key is missing or is an old Gemini key (does not start with gsk_)
    if (!savedKey || !savedKey.startsWith('gsk_')) {
        savedKey = DEFAULT_API_KEY;
        localStorage.setItem('fraudshield_api_key', savedKey);
    }
    state.apiKey = savedKey;
    el.inputApiKey.value = savedKey;
    el.apiStatusDot.className = 'api-status-badge status-ready';
    showToast('Groq API Key loaded', 'info');
}

function saveApiKey() {
    const key = el.inputApiKey.value.trim();
    if (!key) {
        showToast('Please enter a valid API key', 'error');
        return;
    }
    localStorage.setItem('fraudshield_api_key', key);
    state.apiKey = key;
    el.apiStatusDot.className = 'api-status-badge status-ready';
    closeApiModal();
    showToast('API Key saved successfully', 'success');

    // Trigger auto-generation if pending
    if (state.generateOnKeySave && state.imageBase64) {
        state.generateOnKeySave = false;
        triggerGeneration();
    }
}

function clearApiKey() {
    localStorage.removeItem('fraudshield_api_key');
    state.apiKey = '';
    el.inputApiKey.value = '';
    el.apiStatusDot.className = 'api-status-badge status-missing';
    showToast('API Key removed', 'info');
}

function openApiModal() {
    el.apiModal.classList.remove('hidden');
}

function closeApiModal() {
    el.apiModal.classList.add('hidden');
}

// Toggle Masking on Password Field
el.btnToggleKeyVisibility.addEventListener('click', () => {
    const type = el.inputApiKey.type === 'password' ? 'text' : 'password';
    el.inputApiKey.type = type;
    const icon = el.btnToggleKeyVisibility.querySelector('i');
    icon.className = type === 'password' ? 'fa-solid fa-eye' : 'fa-solid fa-eye-slash';
});

// ==========================================================================
// UPLOADER DRAG & DROP & COMPRESSION
// ==========================================================================
function handleFileSelect(file) {
    if (!file) return;
    
    // Validate MIME type
    const validTypes = ['image/png', 'image/jpeg', 'image/webp'];
    if (!validTypes.includes(file.type)) {
        showToast('Unsupported file type. Please upload a PNG, JPG, or WEBP image.', 'error');
        return;
    }
    
    // Validate Size (Max 10MB)
    if (file.size > 10 * 1024 * 1024) {
        showToast('Image is too large. Max size is 10MB.', 'error');
        return;
    }

    state.imageMimeType = file.type;
    el.previewFilename.textContent = file.name;

    // Load file and resize to optimize bandwidth/token consumption
    const reader = new FileReader();
    reader.onload = function(e) {
        const img = new Image();
        img.onload = function() {
            // Compress Image on Canvas to maximum of 1200px width/height
            const canvas = document.createElement('canvas');
            let width = img.width;
            let height = img.height;
            const maxDim = 1200;

            if (width > maxDim || height > maxDim) {
                if (width > height) {
                    height = Math.round((height * maxDim) / width);
                    width = maxDim;
                } else {
                    width = Math.round((width * maxDim) / height);
                    height = maxDim;
                }
            }

            canvas.width = width;
            canvas.height = height;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0, width, height);

            // Export to JPEG base64 (very light)
            const compressedBase64 = canvas.toDataURL('image/jpeg', 0.85);
            state.imageBase64 = compressedBase64.split(',')[1];
            state.previewUrl = compressedBase64;
            state.imageMimeType = 'image/jpeg';

            // Update UI Preview
            el.previewImage.src = compressedBase64;
            el.dropZonePrompt.classList.add('hidden');
            el.dropZonePreview.classList.remove('hidden');
            showToast('Image uploaded and optimized', 'success');

            // Auto-trigger generation
            if (state.apiKey) {
                triggerGeneration();
            } else {
                state.generateOnKeySave = true;
                showToast('Please set your API key to start automatic generation.', 'info');
                openApiModal();
            }
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

function removeImage() {
    state.imageBase64 = '';
    state.imageMimeType = '';
    state.previewUrl = '';
    el.previewImage.src = '';
    el.fileInput.value = '';
    el.dropZonePreview.classList.add('hidden');
    el.dropZonePrompt.classList.remove('hidden');
    showToast('Evidence removed', 'info');
}

document.addEventListener('DOMContentLoaded', () => {
    loadApiKey();
    initLanguage();
});

// Drag Over Events
el.dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    el.dropZone.classList.add('dragover');
});

el.dropZone.addEventListener('dragleave', () => {
    el.dropZone.classList.remove('dragover');
});

el.dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    el.dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
        handleFileSelect(e.dataTransfer.files[0]);
    }
});

el.dropZone.addEventListener('click', () => {
    el.fileInput.click();
});

el.fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFileSelect(e.target.files[0]);
    }
});

el.btnRemoveImage.addEventListener('click', (e) => {
    e.stopPropagation(); // Avoid triggering file selection
    removeImage();
});

// ==========================================================================
// DYNAMIC TAB NAVIGATION
// ==========================================================================
el.tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
        const targetTab = btn.getAttribute('data-tab');
        
        // Deactivate all
        el.tabButtons.forEach(b => b.classList.remove('active'));
        el.tabContents.forEach(c => c.classList.remove('active'));
        
        // Activate target
        btn.classList.add('active');
        document.getElementById(targetTab).classList.add('active');
    });
});

// ==========================================================================
// COMPLAINT GENERATION (GEMINI API)
// ==========================================================================
async function triggerGeneration() {
    if (!state.apiKey) {
        showToast('API Key missing. Click the API Key button in the header.', 'error');
        openApiModal();
        return;
    }
    if (!state.imageBase64) {
        showToast('Please upload an evidence image first.', 'error');
        return;
    }

    // Enter Loading State
    state.isBodyManuallyEdited = false;
    el.outputEmptyState.classList.add('hidden');
    el.outputLoadedState.classList.add('hidden');
    el.outputLoadingState.classList.remove('hidden');
    el.btnDownloadReport.style.display = 'none'; // Hide threat report download button while analyzing
    setLoadingStep(1);

    const todayDate = new Date().toISOString().split('T')[0];
    const targetLangName = state.language === 'hi' ? 'Hindi' : (state.language === 'te' ? 'Telugu' : 'English');

    const prompt = `
You MUST return your output in the following language: ${targetLangName}. Translate all user-facing text, descriptions, titles, categories, subjects, email bodies, threat reports, and checklist step titles/descriptions to ${targetLangName}.

First, perform an initial assessment of the attached image. Scrutinize the screenshot to determine if it contains an active cybersecurity threat/scam (such as a phishing email, spoofed brand message, smishing SMS text, fake invoice/receipt scam, tech support fraud webpage) OR if it represents a legitimate, safe communication with no red flags (such as a genuine newsletter, legitimate purchase confirmation from a verified domain, official password reset, standard notification).

You MUST return your output as a SINGLE VALID JSON object. Do not include markdown code block formatting (like \`\`\`json) in the response outside of the raw text response; just provide the raw JSON. The JSON structure must be:
{
  "isThreat": true or false,
  "detectedCategory": "Human-readable classification (e.g. 'Phishing Email', 'SMS Smishing', or 'Legitimate Communication')",
  "detectedRecipient": "Name of the specific authority, bank, registrar, or abuse team to report this to (e.g. 'Chase Bank Fraud Dept', 'National Cyber Crime Portal'). If it is a safe/legitimate email, set this to 'None (No Action Required)'",
  "reportingEmail": "Abuse/reporting email address corresponding to that recipient (e.g. 'abuse@chase.com', 'report@phishing.gov'). If safe/legitimate, set to 'N/A'",
  "subject": "Formulated subject line. If threat, make it professional and urgent suited for the abuse desk. If safe, set to 'Legitimate Communication Detected'",
  "body": "Formal letter/email body text. If threat, write a formal complaint addressed to the detected recipient reporting the visual details of the scam. If safe, write a friendly, helpful paragraph explaining that FraudShield analyzed the image and determined it appears to be a legitimate, safe message, and no complaint is needed.",
  "threats": "Detailed Markdown list. If threat, explain threat indicators, key extracted data, mismatched domains, and threat mechanism. If safe, explain 'Legitimacy Indicators' showing why this email is safe (e.g., sender domain alignment, clean links, normal formatting, no urgent threats).",
  "checklist": [
    {
      "title": "Short title of step",
      "description": "Short explanation of why this step is critical"
    }
  ]
}

Guidelines for the Fields:
1. "isThreat": Set to true if there is any evidence of phishing, scam, spoofing, or fraudulent activity. Set to false if it appears completely clean and legitimate.
2. "detectedCategory": Analyze the screenshot and provide a clear category name. If safe, classify it as "Legitimate/Safe Email" or "Legitimate Notification".
3. "detectedRecipient": For scams, deduce who should receive the report based on the spoofed brand or nature of fraud. For safe emails, use "None (No Action Required)".
4. "reportingEmail": Find the standard reporting email for that specific entity. Use placeholders like "abuse@company.com" or a realistic reporting address if it's a known brand. For safe emails, set to "N/A".
5. "subject": Formulate an actionable subject line.
6. "body": 
   - If threat: Write a complete, detailed, formal complaint letter to the appropriate division. Describe sender details, timestamps, URLs, spoofed logos, etc., extracted from the image. Use the current date: ${todayDate}. Use bracketed placeholders like "[Victim Name]" for customizable details.
   - If safe: Write a polite, clear notification stating that FraudShield scanned the communication and found no threats. Explain that the user can safely keep it.
7. "threats": 
   - If threat: Write a comprehensive threat analysis in markdown including severity level (Low/Medium/High), indicators found, and technical threat mechanism.
   - If safe: Write a markdown analysis detailing the legitimacy indicators (why it is safe) and confirming no dangerous content was detected.
8. "checklist": 
   - If threat: Provide 4 to 6 critical security checklist actions for the victim based on the scam type (e.g., "Freeze credit cards", "Reset credentials with MFA", "Report to watchdog portals", "Run antivirus/malware search").
   - If safe: Provide 3 to 4 best practices for safe email management (e.g., "Verify headers if uncertain", "Avoid typing credentials from links", "Keep systems updated").
`;

    try {
        await sleep(600);
        setLoadingStep(2);

        const result = await callGroqAPI(prompt);
        setLoadingStep(3);
        await sleep(600);

        state.generatedData = parseResponseJson(result);
        
        // Update Auto-detection results in UI
        if (state.generatedData) {
            const cat = state.generatedData.detectedCategory || 'Unclassified';
            const rec = state.generatedData.detectedRecipient || 'General Authority';
            const email = state.generatedData.reportingEmail || 'N/A';
            
            state.detectedEmail = email;
            
            el.detectedCategoryText.textContent = cat;
            el.detectedRecipientText.textContent = rec;
            el.detectedEmailText.textContent = email;
            
            // Toggle safe-email style on the summary card
            const summaryCard = document.querySelector('.auto-detection-summary');
            if (summaryCard) {
                if (state.generatedData.isThreat === false) {
                    summaryCard.classList.add('safe-email');
                } else {
                    summaryCard.classList.remove('safe-email');
                }
            }
            
            renderOutput(email);
        }
        
        el.outputLoadingState.classList.add('hidden');
        el.outputLoadedState.classList.remove('hidden');
        showToast('Complaint generated successfully!', 'success');

    } catch (error) {
        console.error('Error generating complaint:', error);
        el.outputLoadingState.classList.add('hidden');
        el.outputEmptyState.classList.remove('hidden');
        showToast(error.message || 'An error occurred during API communication', 'error');
    }
}

// Helper: Delay function for step visibility
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Progress Steps indicator manipulation
function setLoadingStep(stepNum) {
    // Reset all
    el.step1.className = 'loading-step';
    el.step2.className = 'loading-step';
    el.step3.className = 'loading-step';

    el.step1.querySelector('.step-icon').innerHTML = '<i class="fa-regular fa-circle"></i>';
    el.step2.querySelector('.step-icon').innerHTML = '<i class="fa-regular fa-circle"></i>';
    el.step3.querySelector('.step-icon').innerHTML = '<i class="fa-regular fa-circle"></i>';

    if (stepNum >= 1) {
        el.step1.className = stepNum === 1 ? 'loading-step current' : 'loading-step completed';
        el.step1.querySelector('.step-icon').innerHTML = stepNum === 1 ? '<i class="fa-solid fa-circle-notch fa-spin"></i>' : '<i class="fa-solid fa-circle-check"></i>';
    }
    if (stepNum >= 2) {
        el.step2.className = stepNum === 2 ? 'loading-step current' : 'loading-step completed';
        el.step2.querySelector('.step-icon').innerHTML = stepNum === 2 ? '<i class="fa-solid fa-circle-notch fa-spin"></i>' : '<i class="fa-solid fa-circle-check"></i>';
    }
    if (stepNum >= 3) {
        el.step3.className = 'loading-step current';
        el.step3.querySelector('.step-icon').innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i>';
    }
}

// Groq Multimodal Chat Completions API Call
async function callGroqAPI(promptText) {
    const url = 'https://api.groq.com/openai/v1/chat/completions';

    const requestBody = {
        model: 'meta-llama/llama-4-scout-17b-16e-instruct',
        messages: [
            {
                role: 'user',
                content: [
                    {
                        type: 'text',
                        text: promptText
                    },
                    {
                        type: 'image_url',
                        image_url: {
                            url: `data:${state.imageMimeType};base64,${state.imageBase64}`
                        }
                    }
                ]
            }
        ],
        response_format: {
            type: 'json_object'
        }
    };

    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${state.apiKey}`
        },
        body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const errMsg = errorData.error?.message || `Groq API request failed with status ${response.status}`;
        throw new Error(errMsg);
    }

    const data = await response.json();
    
    if (!data.choices?.[0]?.message?.content) {
        throw new Error('Invalid or empty response from Groq API');
    }

    return data.choices[0].message.content;
}

// Parse Response text into JSON
function parseResponseJson(responseText) {
    try {
        // Strip markdown backticks if returned despite prompt instruction
        let cleaned = responseText.trim();
        if (cleaned.startsWith('```')) {
            cleaned = cleaned.replace(/^```json\s*/, '').replace(/```$/, '');
        }
        return JSON.parse(cleaned);
    } catch (e) {
        console.warn('Direct JSON parse failed, attempting regex cleanup...', e);
        // Fallback: search for JSON structure
        const jsonMatch = responseText.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
            try {
                return JSON.parse(jsonMatch[0]);
            } catch (innerError) {
                throw new Error('Failed to parse Gemini response as JSON');
            }
        }
        throw new Error('API returned malformed output that could not be parsed.');
    }
}

// ==========================================================================
// RENDER OUTPUTS AND EVENTS
// ==========================================================================
function renderOutput(recipientEmail) {
    if (!state.generatedData) return;

    // 1. Email Tab
    el.emailSubject.value = state.generatedData.subject || 'Cyber Incident Complaint Report';
    el.emailBody.value = state.generatedData.body || '';

    // Apply auto-fill details dynamically if available
    updateEmailWithDetails();

    // Show/hide email action buttons depending on whether it is a threat
    if (state.generatedData.isThreat === false) {
        el.btnSendEmail.style.display = 'none';
        el.btnDownloadEmail.style.display = 'none';
        el.btnCopyEmail.style.display = 'none';
    } else {
        el.btnSendEmail.style.display = 'inline-flex';
        el.btnDownloadEmail.style.display = 'inline-flex';
        el.btnCopyEmail.style.display = 'inline-flex';
    }

    // Update mailto link dynamically
    updateMailtoLink(recipientEmail);

    // 2. Threat Analysis Tab (using Marked.js)
    if (window.marked && state.generatedData.threats) {
        el.threatAnalysisContent.innerHTML = marked.parse(state.generatedData.threats);
        el.btnDownloadReport.style.display = 'inline-flex';
    } else {
        el.threatAnalysisContent.textContent = state.generatedData.threats || 'No analysis provided.';
        el.btnDownloadReport.style.display = state.generatedData.threats ? 'inline-flex' : 'none';
    }

    // 3. Checklist Tab
    el.checklistContainer.innerHTML = '';
    const items = state.generatedData.checklist || [];
    
    if (items.length === 0) {
        el.checklistContainer.innerHTML = '<p class="color-text-muted">No specific steps generated.</p>';
    } else {
        items.forEach((item, index) => {
            const itemEl = document.createElement('div');
            itemEl.className = 'checklist-item';
            itemEl.innerHTML = `
                <div class="checkbox-wrapper">
                    <input type="checkbox" id="chk-${index}">
                    <span class="checkmark"></span>
                </div>
                <div class="checklist-text-wrapper">
                    <span class="checklist-title">${item.title}</span>
                    <span class="checklist-desc">${item.description}</span>
                </div>
            `;

            // Toggle Checked Class
            const checkbox = itemEl.querySelector('input');
            checkbox.addEventListener('change', () => {
                if (checkbox.checked) {
                    itemEl.classList.add('checked');
                } else {
                    itemEl.classList.remove('checked');
                }
            });

            // Make clicking card trigger checkbox
            itemEl.addEventListener('click', (e) => {
                if (e.target !== checkbox && !e.target.closest('.checkbox-wrapper')) {
                    checkbox.checked = !checkbox.checked;
                    checkbox.dispatchEvent(new Event('change'));
                }
            });

            el.checklistContainer.appendChild(itemEl);
        });
    }

    // Reset to first tab
    el.tabButtons[0].click();
}

function updateMailtoLink(recipientEmail) {
    const to = recipientEmail || '';
    const subject = encodeURIComponent(el.emailSubject.value);
    const body = encodeURIComponent(el.emailBody.value);
    el.btnSendEmail.href = `mailto:${to}?subject=${subject}&body=${body}`;
}

// Recalculate mailto when user edits body
    el.emailBody.addEventListener('input', () => {
        state.isBodyManuallyEdited = true;
        updateMailtoLink(state.detectedEmail);
    });

// ==========================================================================
// ACTION BUTTONS EVENTS
// ==========================================================================

// Copy Subject line
el.btnCopySubject.addEventListener('click', () => {
    el.emailSubject.select();
    navigator.clipboard.writeText(el.emailSubject.value)
        .then(() => showToast('Subject line copied!', 'success'))
        .catch(() => showToast('Failed to copy text', 'error'));
});

// Copy Entire Email
el.btnCopyEmail.addEventListener('click', () => {
    el.emailBody.select();
    navigator.clipboard.writeText(el.emailBody.value)
        .then(() => showToast('Email body copied!', 'success'))
        .catch(() => showToast('Failed to copy text', 'error'));
});

// Save as text file download
el.btnDownloadEmail.addEventListener('click', () => {
    const subject = el.emailSubject.value;
    const body = el.emailBody.value;
    const fileContent = `SUBJECT: ${subject}\n\n=========================================\n\n${body}`;
    
    const blob = new Blob([fileContent], { type: 'text/plain;charset=utf-8' });
    const tempUrl = URL.createObjectURL(blob);
    
    const downloadLink = document.createElement('a');
    downloadLink.href = tempUrl;
    downloadLink.download = `fraud_complaint_${new Date().toISOString().split('T')[0]}.txt`;
    
    document.body.appendChild(downloadLink);
    downloadLink.click();
    document.body.removeChild(downloadLink);
    
    URL.revokeObjectURL(tempUrl);
    showToast('Complaint file saved!', 'success');
});

// ==========================================================================
// INITIAL SETUP LISTENERS
// ==========================================================================
el.btnApiConfig.addEventListener('click', openApiModal);
el.btnSaveApi.addEventListener('click', saveApiKey);
el.btnCancelApi.addEventListener('click', closeApiModal);
el.btnCloseModalX.addEventListener('click', closeApiModal);
el.apiModal.addEventListener('click', (e) => {
    if (e.target === el.apiModal) closeApiModal();
});

// ==========================================================================
// MULTI-VIEW NAVIGATION SWITCHER
// ==========================================================================
el.navTabs.forEach(tab => {
    tab.addEventListener('click', () => {
        const targetView = tab.getAttribute('data-view');
        
        // Toggle active tab class
        el.navTabs.forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        
        // Toggle views
        el.appViews.forEach(v => {
            if (v.id === targetView) {
                v.classList.remove('hidden');
            } else {
                v.classList.add('hidden');
            }
        });
    });
});

// ==========================================================================
// GROQ TEXT & CHAT API HELPERS
// ==========================================================================
async function callGroqTextAPI(promptText) {
    const url = 'https://api.groq.com/openai/v1/chat/completions';

    const requestBody = {
        model: 'meta-llama/llama-4-scout-17b-16e-instruct',
        messages: [
            {
                role: 'user',
                content: promptText
            }
        ],
        response_format: {
            type: 'json_object'
        }
    };

    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${state.apiKey}`
        },
        body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const errMsg = errorData.error?.message || `Groq API request failed with status ${response.status}`;
        throw new Error(errMsg);
    }

    const data = await response.json();
    return data.choices[0].message.content;
}

async function callGroqChatAPI(messages) {
    const url = 'https://api.groq.com/openai/v1/chat/completions';

    const requestBody = {
        model: 'meta-llama/llama-4-scout-17b-16e-instruct',
        messages: messages
    };

    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${state.apiKey}`
        },
        body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        const errMsg = errorData.error?.message || `Groq API request failed with status ${response.status}`;
        throw new Error(errMsg);
    }

    const data = await response.json();
    return data.choices[0].message.content;
}

// ==========================================================================
// PHISHING LINK ANALYZER CONTROL LOGIC
// ==========================================================================
async function triggerUrlAnalysis() {
    const urlInput = el.inputScamUrl.value.trim();
    if (!urlInput) {
        showToast('Please enter a suspicious URL first.', 'error');
        return;
    }

    if (!state.apiKey) {
        showToast('API Key missing. Click the API Key button in the header.', 'error');
        openApiModal();
        return;
    }

    // Toggle UI States
    el.urlEmptyState.classList.add('hidden');
    el.urlLoadedState.classList.add('hidden');
    el.urlLoadingState.classList.remove('hidden');

    const targetLangName = state.language === 'hi' ? 'Hindi' : (state.language === 'te' ? 'Telugu' : 'English');

    const prompt = `
You MUST return your output in the following language: ${targetLangName}. Translate all user-facing text, explanations, education, dos and donts lists, technical analysis markdown, recommendations, and classifications to ${targetLangName}.

Analyze the following URL for cybersecurity risks, phishing indicators, and spoofing signatures: "${urlInput}"

You MUST return your output as a SINGLE VALID JSON object. Do not include markdown code block formatting (like \`\`\`json) in the response outside of the raw text response; just provide the raw JSON. The JSON structure must be:
{
  "safetyScore": 15, // Integer 0 to 100, where 100 is completely safe, 70+ is warning/minor, and 0-50 is high risk/phishing
  "riskLevel": "SAFE" or "WARNING" or "CRITICAL",
  "targetBrand": "Name of spoofed organization/brand (e.g. 'Netflix', 'PayPal', 'Chase Bank') or 'None'",
  "riskClassification": "Short tag (e.g. 'Phishing Page', 'Typosquatting Domain', 'Unsafe Protocol', 'Secure URL')",
  "simpleExplanation": "Explain neatly and in a very simple, non-technical way for a general user what this link is and why it is suspicious/unsafe (or why it is safe). Keep it to 2-3 sentences.",
  "urlEducation": "Provide a simple educational explanation about this specific URL structure. Explain the difference between the actual domain name (e.g. the provider registry) and subdomains, or mention tricks scammers use like typosquatting or insecure HTTP protocols.",
  "dosAndDonts": {
    "dos": [
      "Short action item 1 (e.g., 'Double check the website certificate manually')",
      "Short action item 2"
    ],
    "donts": [
      "Short avoid item 1 (e.g., 'Do NOT click links inside emails from this domain')",
      "Short avoid item 2"
    ]
  },
  "technicalAnalysis": "Markdown detailing the domain technical assessment, registry cues, typosquatting checks, SSL protocol, path risks, and subdomains.",
  "recommendations": [
    "Do NOT visit this link or enter any login credentials.",
    "Detail recommendations..."
  ]
}
`;

    try {
        const result = await callGroqTextAPI(prompt);
        const parsed = JSON.parse(result);

        // Render URL Analysis Dashboard
        const score = parsed.safetyScore !== undefined ? parsed.safetyScore : 50;
        const risk = parsed.riskLevel || 'WARNING';
        const brand = parsed.targetBrand || 'None';
        const classification = parsed.riskClassification || 'Suspicious URL';
        const simple = parsed.simpleExplanation || 'No summary available.';
        const edu = parsed.urlEducation || 'No educational explanation available.';
        const analysis = parsed.technicalAnalysis || 'No details provided.';
        const recs = parsed.recommendations || [];

        // 1. Draw Safety Meter (circular progress)
        el.urlScoreText.textContent = `${score}%`;
        const scoreColor = score >= 70 ? 'var(--accent-success)' : (score >= 40 ? '#f59e0b' : 'var(--accent-danger)');
        const deg = (score / 100) * 360;
        el.urlProgressCircle.style.background = `conic-gradient(${scoreColor} ${deg}deg, rgba(255,255,255,0.05) ${deg}deg)`;

        // 2. Safety Status Texts & Badges
        el.urlSafetyStatus.textContent = risk === 'SAFE' ? 'DOMAIN SECURE' : (risk === 'WARNING' ? 'SUSPICIOUS DOMAIN' : 'CRITICAL THREAT');
        el.urlSafetyStatus.className = risk.toLowerCase();
        
        el.urlRiskBadge.textContent = classification;
        el.urlRiskBadge.className = `badge badge-${risk.toLowerCase()}`;

        // 3. Analyzed URL Display
        el.urlDisplayText.textContent = urlInput;

        // 4. Target Brand Banner
        if (brand.toLowerCase() !== 'none' && brand.trim() !== '') {
            el.urlTargetBrand.textContent = brand;
            el.urlBrandBanner.classList.remove('hidden');
        } else {
            el.urlBrandBanner.classList.add('hidden');
        }

        // 5. Populate Simple Explanation and URL Education Card
        el.urlSimpleExpl.textContent = simple;
        el.urlEduExpl.textContent = edu;

        // 6. Populate Do's and Don'ts Lists
        el.urlDosList.innerHTML = '';
        const dos = parsed.dosAndDonts?.dos || [];
        if (dos.length === 0) {
            el.urlDosList.innerHTML = '<li style="margin-bottom: 4px;">Verify the domain spelling.</li><li style="margin-bottom: 4px;">Escalate to security desks.</li>';
        } else {
            dos.forEach(item => {
                const li = document.createElement('li');
                li.style.marginBottom = '4px';
                li.textContent = item;
                el.urlDosList.appendChild(li);
            });
        }

        el.urlDontsList.innerHTML = '';
        const donts = parsed.dosAndDonts?.donts || [];
        if (donts.length === 0) {
            el.urlDontsList.innerHTML = '<li style="margin-bottom: 4px;">Do NOT input personal data.</li><li style="margin-bottom: 4px;">Do NOT click login prompts.</li>';
        } else {
            donts.forEach(item => {
                const li = document.createElement('li');
                li.style.marginBottom = '4px';
                li.textContent = item;
                el.urlDontsList.appendChild(li);
            });
        }

        // 7. Indicators Report (Marked)
        if (window.marked) {
            el.urlIndicatorsContent.innerHTML = marked.parse(analysis);
        } else {
            el.urlIndicatorsContent.textContent = analysis;
        }

        // 6. Action Items List
        el.urlActionsContainer.innerHTML = '';
        if (recs.length === 0) {
            el.urlActionsContainer.innerHTML = '<p class="color-text-muted">No safety steps generated.</p>';
        } else {
            recs.forEach((rec, idx) => {
                const itemEl = document.createElement('div');
                itemEl.className = 'checklist-item';
                itemEl.innerHTML = `
                    <div class="checkbox-wrapper">
                        <input type="checkbox" id="url-chk-${idx}">
                        <span class="checkmark"></span>
                    </div>
                    <div class="checklist-text-wrapper">
                        <span class="checklist-title">${rec}</span>
                    </div>
                `;
                const checkbox = itemEl.querySelector('input');
                checkbox.addEventListener('change', () => {
                    if (checkbox.checked) {
                        itemEl.classList.add('checked');
                    } else {
                        itemEl.classList.remove('checked');
                    }
                });
                itemEl.addEventListener('click', (e) => {
                    if (e.target !== checkbox && !e.target.closest('.checkbox-wrapper')) {
                        checkbox.checked = !checkbox.checked;
                        checkbox.dispatchEvent(new Event('change'));
                    }
                });
                el.urlActionsContainer.appendChild(itemEl);
            });
        }

        // Transition UI States
        el.urlLoadingState.classList.add('hidden');
        el.urlLoadedState.classList.remove('hidden');
        showToast('Threat scan complete!', 'success');

    } catch (e) {
        console.error('URL Scan failed:', e);
        el.urlLoadingState.classList.add('hidden');
        el.urlEmptyState.classList.remove('hidden');
        showToast(e.message || 'Threat scan failed', 'error');
    }
}

el.btnAnalyzeUrl.addEventListener('click', triggerUrlAnalysis);
el.inputScamUrl.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        triggerUrlAnalysis();
    }
});

// ==========================================================================
// AI SECURITY ASSISTANT CHATBOT LOGIC
// ==========================================================================
async function handleChatSubmit() {
    const text = el.inputChatMessage.value.trim();
    if (!text) return;

    if (!state.apiKey) {
        showToast('API Key missing. Click the API Key button in the header.', 'error');
        openApiModal();
        return;
    }

    appendChatMessage(text, 'user');
    el.inputChatMessage.value = '';
    state.chatHistory.push({ role: 'user', content: text });

    const loadingBubble = appendChatLoadingBubble();
    
    try {
        const responseText = await callGroqChatAPI(state.chatHistory);
        loadingBubble.remove();
        appendChatMessage(responseText, 'assistant');
        state.chatHistory.push({ role: 'assistant', content: responseText });
    } catch (e) {
        console.error('Chatbot request failed:', e);
        loadingBubble.remove();
        appendChatMessage(`Sorry, I encountered an error during API communication: ${e.message || 'Unknown issue'}. Please try again.`, 'assistant');
        showToast('Chatbot response failed', 'error');
    }
}

async function sendQuickChatMessage(query) {
    if (!state.apiKey) {
        showToast('API Key missing. Click the API Key button in the header.', 'error');
        openApiModal();
        return;
    }
    
    appendChatMessage(query, 'user');
    state.chatHistory.push({ role: 'user', content: query });
    
    const loadingBubble = appendChatLoadingBubble();
    
    try {
        const responseText = await callGroqChatAPI(state.chatHistory);
        loadingBubble.remove();
        appendChatMessage(responseText, 'assistant');
        state.chatHistory.push({ role: 'assistant', content: responseText });
    } catch (e) {
        console.error(e);
        loadingBubble.remove();
        appendChatMessage(`Sorry, I failed to fetch a response: ${e.message}`, 'assistant');
    }
}

function appendChatMessage(text, sender) {
    const msgEl = document.createElement('div');
    msgEl.className = `chat-message message-${sender}`;
    msgEl.style.display = 'flex';
    msgEl.style.gap = '12px';
    msgEl.style.alignItems = 'flex-start';
    if (sender === 'user') {
        msgEl.style.flexDirection = 'row-reverse';
    }

    let avatarHtml = '';
    let bubbleStyle = '';
    
    if (sender === 'assistant') {
        avatarHtml = `
            <div class="chat-avatar" style="width: 32px; height: 32px; border-radius: 50%; background: rgba(6, 182, 212, 0.15); border: 1px solid rgba(6, 182, 212, 0.3); display: flex; align-items: center; justify-content: center; color: var(--accent-cyan); flex-shrink: 0; font-size: 0.9rem;">
                <i class="fa-solid fa-shield-halved"></i>
            </div>
        `;
        bubbleStyle = `background: var(--bg-card); border: 1px solid var(--border-color); padding: 12px 16px; border-radius: 0 14px 14px 14px; max-width: 80%; font-size: 0.9rem; line-height: 1.5;`;
    } else {
        avatarHtml = `
            <div class="chat-avatar" style="width: 32px; height: 32px; border-radius: 50%; background: rgba(99, 102, 241, 0.15); border: 1px solid rgba(99, 102, 241, 0.3); display: flex; align-items: center; justify-content: center; color: var(--accent-indigo); flex-shrink: 0; font-size: 0.9rem;">
                <i class="fa-solid fa-user"></i>
            </div>
        `;
        bubbleStyle = `background: linear-gradient(135deg, var(--accent-indigo) 0%, rgba(99, 102, 241, 0.7) 100%); border: 1px solid rgba(99, 102, 241, 0.25); color: #ffffff; padding: 12px 16px; border-radius: 14px 0 14px 14px; max-width: 80%; font-size: 0.9rem; line-height: 1.5; box-shadow: 0 4px 12px rgba(99, 102, 241, 0.1);`;
    }

    let contentHtml = '';
    if (window.marked && sender === 'assistant') {
        contentHtml = marked.parse(text);
    } else {
        contentHtml = `<p>${text.replace(/\n/g, '<br>')}</p>`;
    }

    msgEl.innerHTML = `
        ${avatarHtml}
        <div class="message-bubble" style="${bubbleStyle}">
            ${contentHtml}
        </div>
    `;

    el.chatMessagesContainer.appendChild(msgEl);
    el.chatMessagesContainer.scrollTop = el.chatMessagesContainer.scrollHeight;
}

function appendChatLoadingBubble() {
    const msgEl = document.createElement('div');
    msgEl.className = 'chat-message message-assistant';
    msgEl.style.display = 'flex';
    msgEl.style.gap = '12px';
    msgEl.style.alignItems = 'flex-start';

    msgEl.innerHTML = `
        <div class="chat-avatar" style="width: 32px; height: 32px; border-radius: 50%; background: rgba(6, 182, 212, 0.15); border: 1px solid rgba(6, 182, 212, 0.3); display: flex; align-items: center; justify-content: center; color: var(--accent-cyan); flex-shrink: 0; font-size: 0.9rem;">
            <i class="fa-solid fa-shield-halved"></i>
        </div>
        <div class="message-bubble" style="background: var(--bg-card); border: 1px solid var(--border-color); padding: 12px 16px; border-radius: 0 14px 14px 14px; max-width: 80%; font-size: 0.9rem; line-height: 1.5;">
            <div class="typing-dots">
                <span></span>
                <span></span>
                <span></span>
            </div>
        </div>
    `;

    el.chatMessagesContainer.appendChild(msgEl);
    el.chatMessagesContainer.scrollTop = el.chatMessagesContainer.scrollHeight;
    return msgEl;
}

el.btnSendChat.addEventListener('click', handleChatSubmit);
el.inputChatMessage.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        e.preventDefault();
        handleChatSubmit();
    }
});

el.quickQueryCards.forEach(card => {
    card.addEventListener('click', () => {
        const query = card.getAttribute('data-query');
        if (query) {
            sendQuickChatMessage(query);
        }
    });
});

// ==========================================================================
// DETAILS ACCORDION AUTO-FILL INTERACTIVE LOGIC
// ==========================================================================
function updateEmailWithDetails() {
    if (!state.generatedData || !state.generatedData.body) return;
    if (state.isBodyManuallyEdited) return; // Prevent overwriting user edits

    let body = state.generatedData.body;
    
    const name = el.inputVictimName.value.trim();
    const phone = el.inputVictimPhone.value.trim();
    const extra = el.inputVictimExtra.value.trim();

    if (name) {
        body = body.replace(/\[Victim Name\]/gi, name);
    }
    if (phone) {
        body = body.replace(/\[Victim Phone\]/gi, phone);
    }
    if (extra) {
        body = body.replace(/\[Victim Account\]/gi, extra)
                   .replace(/\[Victim Details\]/gi, extra)
                   .replace(/\[Account Details\]/gi, extra)
                   .replace(/\[Account Number\]/gi, extra);
    }

    el.emailBody.value = body;
    updateMailtoLink(state.detectedEmail);
}

el.inputVictimName.addEventListener('input', updateEmailWithDetails);
el.inputVictimPhone.addEventListener('input', updateEmailWithDetails);
el.inputVictimExtra.addEventListener('input', updateEmailWithDetails);

// ==========================================================================
// THREAT REPORT EXPORT & CHAT HISTORY CLEAR HANDLERS
// ==========================================================================
el.btnDownloadReport.addEventListener('click', () => {
    if (!state.generatedData) return;
    if (typeof html2pdf === 'undefined') {
        showToast('PDF library not loaded yet. Check your connection.', 'error');
        return;
    }

    showToast('Generating PDF Report...', 'info');

    const category = state.generatedData.detectedCategory || 'Unclassified';
    const recipient = state.generatedData.detectedRecipient || 'N/A';
    const email = state.generatedData.reportingEmail || 'N/A';
    const threats = state.generatedData.threats || '';

    // Create container for PDF document styled in white background for printing
    const reportEl = document.createElement('div');
    reportEl.style.padding = '35px';
    reportEl.style.fontFamily = "'Inter', sans-serif";
    reportEl.style.color = '#1e293b';
    reportEl.style.backgroundColor = '#ffffff';

    // Header styling
    let headerHtml = `
        <div style="border-bottom: 2px solid #6366f1; padding-bottom: 15px; margin-bottom: 25px; display: flex; align-items: center; justify-content: space-between;">
            <div>
                <h1 style="font-family: 'Outfit', sans-serif; font-size: 24px; color: #1e1b4b; margin: 0; font-weight: 700;">Fraud<span style="color: #6366f1;">Shield</span></h1>
                <p style="font-size: 11px; color: #64748b; margin: 2px 0 0 0; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600;">AI Cybersecurity Threat Report</p>
            </div>
            <div style="text-align: right;">
                <p style="font-size: 11px; color: #64748b; margin: 0;">Report Date: ${new Date().toLocaleDateString()}</p>
                <p style="font-size: 11px; color: #64748b; margin: 2px 0 0 0;">Time: ${new Date().toLocaleTimeString()}</p>
            </div>
        </div>
    `;

    // Metadata table card
    let metadataHtml = `
        <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; margin-bottom: 25px;">
            <h3 style="font-family: 'Outfit', sans-serif; font-size: 13px; color: #0f172a; margin-top: 0; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.03em; font-weight: 700; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px;">Incident Assessment Summary</h3>
            <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
                <tr>
                    <td style="padding: 6px 0; color: #64748b; width: 35%;">Classification:</td>
                    <td style="padding: 6px 0; color: #0f172a; font-weight: 600;">${category}</td>
                </tr>
                <tr>
                    <td style="padding: 6px 0; color: #64748b;">Threat Assessment:</td>
                    <td style="padding: 6px 0; color: ${state.generatedData.isThreat ? '#f43f5e' : '#10b981'}; font-weight: 700;">
                        ${state.generatedData.isThreat ? 'HIGH RISK (ACTIVE THREAT)' : 'SAFE (LEGITIMATE COMMUNICATION)'}
                    </td>
                </tr>
                <tr>
                    <td style="padding: 6px 0; color: #64748b;">Target Authority:</td>
                    <td style="padding: 6px 0; color: #0f172a; font-weight: 500;">${recipient}</td>
                </tr>
                <tr>
                    <td style="padding: 6px 0; color: #64748b;">Abuse Reporting Destination:</td>
                    <td style="padding: 6px 0; color: #6366f1; font-weight: 500; font-family: monospace;">${email}</td>
                </tr>
            </table>
        </div>
    `;

    // Threat details section with custom style injections to override PDF printing layout
    let bodyHtml = `
        <div style="margin-bottom: 25px;">
            <h3 style="font-family: 'Outfit', sans-serif; font-size: 15px; color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin-bottom: 12px; font-weight: 700;">Detailed Threat Analysis</h3>
            <div class="pdf-markdown" style="font-size: 12px; line-height: 1.6; color: #334155;">
                <style>
                    .pdf-markdown h3 { font-family: 'Outfit', sans-serif; font-size: 13px; color: #0f172a; margin-top: 15px; margin-bottom: 8px; border-bottom: 1px solid #f1f5f9; padding-bottom: 4px; font-weight: 600; }
                    .pdf-markdown ul { padding-left: 18px; margin-bottom: 12px; }
                    .pdf-markdown li { margin-bottom: 5px; }
                    .pdf-markdown strong { color: #0f172a; font-weight: 600; }
                    .pdf-markdown blockquote { border-left: 3px solid #6366f1; background-color: #f8fafc; padding: 8px 12px; margin: 12px 0; border-radius: 0 6px 6px 0; font-style: italic; color: #475569; }
                </style>
                ${window.marked ? marked.parse(threats) : threats.replace(/\n/g, '<br>')}
            </div>
        </div>
    `;

    // Next steps checklist
    let checklistHtml = '';
    if (state.generatedData.checklist && state.generatedData.checklist.length > 0) {
        checklistHtml = `
            <div style="margin-bottom: 25px; page-break-inside: avoid;">
                <h3 style="font-family: 'Outfit', sans-serif; font-size: 15px; color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin-bottom: 12px; font-weight: 700;">Immediate Safety Recommendations</h3>
                <div style="display: flex; flex-direction: column; gap: 8px;">
        `;
        state.generatedData.checklist.forEach((item, index) => {
            checklistHtml += `
                <div style="border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px; background-color: #f8fafc; display: flex; gap: 10px; align-items: flex-start; margin-bottom: 6px;">
                    <div style="width: 18px; height: 18px; border-radius: 50%; background-color: #e2e8f0; display: flex; align-items: center; justify-content: center; margin-top: 2px; color: #475569; font-size: 10px; font-weight: bold; flex-shrink: 0;">${index + 1}</div>
                    <div>
                        <h4 style="font-size: 12px; color: #0f172a; margin: 0; font-weight: 600;">${item.title}</h4>
                        <p style="font-size: 11px; color: #475569; margin: 2px 0 0 0; line-height: 1.4;">${item.description}</p>
                    </div>
                </div>
            `;
        });
        checklistHtml += `
                </div>
            </div>
        `;
    }

    // Disclaimer footer
    let footerHtml = `
        <div style="border-top: 1px solid #e2e8f0; padding-top: 15px; margin-top: 30px; text-align: center; font-size: 9px; color: #94a3b8; page-break-inside: avoid; line-height: 1.4;">
            <p><strong>Disclaimer:</strong> This automated threat assessment report was generated by FraudShield AI using visual evidence analysis.</p>
            <p style="margin-top: 2px;">Keep this PDF for your security logs, banking fraud notifications, or corporate IT security escalation desks.</p>
        </div>
    `;

    // Fetch personal details inputs
    const victimName = el.inputVictimName.value.trim();
    const victimPhone = el.inputVictimPhone.value.trim();
    const victimExtra = el.inputVictimExtra.value.trim();

    let reporterInfoHtml = '';
    if (victimName || victimPhone || victimExtra) {
        reporterInfoHtml = `
            <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; margin-bottom: 25px; page-break-inside: avoid;">
                <h3 style="font-family: 'Outfit', sans-serif; font-size: 13px; color: #0f172a; margin-top: 0; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.03em; font-weight: 700; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px;">Personal Details (Reporter Info)</h3>
                <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
                    ${victimName ? `<tr><td style="padding: 6px 0; color: #64748b; width: 35%;">Reporter Name:</td><td style="padding: 6px 0; color: #0f172a; font-weight: 600;">${victimName}</td></tr>` : ''}
                    ${victimPhone ? `<tr><td style="padding: 6px 0; color: #64748b;">Reporter Phone:</td><td style="padding: 6px 0; color: #0f172a; font-weight: 500;">${victimPhone}</td></tr>` : ''}
                    ${victimExtra ? `<tr><td style="padding: 6px 0; color: #64748b;">Additional Context / Details:</td><td style="padding: 6px 0; color: #0f172a; font-weight: 500; font-family: monospace;">${victimExtra}</td></tr>` : ''}
                </table>
            </div>
        `;
    }

    // Assemble PDF DOM
    reportEl.innerHTML = headerHtml + metadataHtml + reporterInfoHtml + bodyHtml + checklistHtml + footerHtml;

    // html2pdf options
    const opt = {
        margin:       10,
        filename:     `fraudshield_threat_report_${new Date().toISOString().split('T')[0]}.pdf`,
        image:        { type: 'jpeg', quality: 0.98 },
        html2canvas:  { scale: 2, useCORS: true, letterRendering: true },
        jsPDF:        { unit: 'mm', format: 'a4', orientation: 'portrait' },
        pagebreak:    { mode: ['avoid-all', 'css', 'legacy'] }
    };

    // Execute PDF conversion and download
    html2pdf().set(opt).from(reportEl).save()
        .then(() => {
            showToast('PDF Threat Report downloaded!', 'success');
        })
        .catch((err) => {
            console.error('PDF Generation failed:', err);
            showToast('Failed to generate PDF', 'error');
        });
});

el.btnClearChat.addEventListener('click', () => {
    state.chatHistory = [
        {
            role: 'system',
            content: getSystemPrompt(state.language)
        }
    ];
    
    const welcomeText = translations[state.language]['chat-welcome'];
    
    el.chatMessagesContainer.innerHTML = `
        <div class="chat-message message-assistant" style="display: flex; gap: 12px; align-items: flex-start;">
            <div class="chat-avatar" style="width: 32px; height: 32px; border-radius: 50%; background: rgba(6, 182, 212, 0.15); border: 1px solid rgba(6, 182, 212, 0.3); display: flex; align-items: center; justify-content: center; color: var(--accent-cyan); flex-shrink: 0; font-size: 0.9rem;">
                <i class="fa-solid fa-shield-halved"></i>
            </div>
            <div class="message-bubble" style="background: var(--bg-card); border: 1px solid var(--border-color); padding: 12px 16px; border-radius: 0 14px 14px 14px; max-width: 80%; font-size: 0.9rem; line-height: 1.5;">
                <p data-i18n="chat-welcome">${welcomeText}</p>
            </div>
        </div>
    `;
    
    const toastMsg = state.language === 'hi' ? 'चैट इतिहास साफ किया गया' : (state.language === 'te' ? 'చాట్ చరిత్ర క్లియర్ చేయబడింది' : 'Chat history cleared');
    showToast(toastMsg, 'info');
});
