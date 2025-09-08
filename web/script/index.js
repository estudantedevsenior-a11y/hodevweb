// =======================
// Entities + Builder
// =======================

class Project {
  constructor(title, description, image, link) {
    this.title = title;
    this.description = description;
    this.image = image;
    this.link = link;
  }
}

class ProjectBuilder {
  constructor() {
    this.title = "";
    this.description = "";
    this.image = "";
    this.link = "#";
  }
  setTitle(title) {
    this.title = title;
    return this;
  }
  setDescription(description) {
    this.description = description;
    return this;
  }
  setImage(image) {
    this.image = image;
    return this;
  }
  setLink(link) {
    this.link = link;
    return this;
  }
  build() {
    return new Project(this.title, this.description, this.image, this.link);
  }
}

// =======================
// Modal Controller
// =======================

class ProjectsModal {
  constructor(modalId, openBtnId, closeBtnId, projectsContainerId) {
    this.modal = document.getElementById(modalId);
    this.openBtn = document.getElementById(openBtnId);
    this.closeBtn = document.getElementById(closeBtnId);
    this.overlay = this.modal.querySelector(".modal__overlay");
    this.container = document.getElementById(projectsContainerId);

    this.initEvents();
  }

  initEvents() {
    this.openBtn.addEventListener("click", () => this.open());
    this.closeBtn.addEventListener("click", () => this.close());
    this.overlay.addEventListener("click", () => this.close());
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") this.close();
    });
  }

  open() {
    this.modal.classList.add("is-active");
  }

  close() {
    this.modal.classList.remove("is-active");
  }

  renderProjects(projects) {
    this.container.innerHTML = "";
    projects.forEach((p) => {
      const card = document.createElement("div");
      card.className = "project-card";
      card.innerHTML = `
        <img src="${p.image}" alt="${p.title}">
        <h3>${p.title}</h3>
        <p>${p.description}</p>
        <a href="${p.link}" target="_blank" rel="noopener noreferrer">Acessar</a>
      `;
      this.container.appendChild(card);
    });
  }
}

// =======================
// Inicialização
// =======================

// ======================================================
// Quando criar os projetos descomente o código abaixo
// ======================================================

// document.addEventListener("DOMContentLoaded", () => {
//   const projects = [
//     new ProjectBuilder()
//       .setTitle("Website Responsivo")
//       .setDescription("Criação de site moderno e adaptável.")
//       .setImage("./assets/projeto1.png")
//       .setLink("https://meusite1.com")
//       .build(),
//     new ProjectBuilder()
//       .setTitle("Landing Page")
//       .setDescription("Página de alta conversão para captação de clientes.")
//       .setImage("./assets/projeto2.png")
//       .setLink("https://meusite2.com")
//       .build(),
//     new ProjectBuilder()
//       .setTitle("Automação com n8n")
//       .setDescription("Fluxos automatizados para otimizar processos.")
//       .setImage("./assets/projeto3.png")
//       .setLink("https://meusite3.com")
//       .build(),
//   ]

//   const modal = new ProjectsModal(
//     "projectsModal",
//     "openProjectsBtn",
//     "closeModalBtn",
//     "projectsContainer"
//   )

//   modal.renderProjects(projects)
// })

/* 
  SECURITY NOTES (XSS & SQLi hardening – client side)
  ---------------------------------------------------
  - Field-specific sanitizers (SRP) with allowlists:
      * Name: only letters (incl. accents), spaces, hyphen, apostrophe.
      * Email: remove chars fora de [a-z0-9._%+-@] e normaliza para minúsculas.
      * Phone: mantém dígitos e um único '+' no início; remove demais.
     / * Message: remove tags HTML, tokens de comentário (/* */ //, --),
/*terminadores (';'), aspas/backticks, chaves {}, backslash, 
sequence "javascript:" e normaliza espaços.
- Unicode NFKC normalization: mitiga homógrafos/compatibility forms.
- Remove control chars (exceto \n e \t na mensagem).
- Limites de tamanho (DoS/payloads grandes).
- Mensagens na UI usam textContent (não innerHTML) para evitar XSS.
- IMPORTANTE: prevenção real de SQL Injection deve ser feita no BACK-END
com consultas parametrizadas/ORM. Este código apenas "higieniza" o input
para reduzir risco antes do envio.
*/

// ============================
// Utils: Normalization & Escaping
// ============================
function normalizeUnicode(str) {
  return (str ?? "").normalize("NFKC");
}

function stripControls(str, { keepNewlines = false } = {}) {
  const re = keepNewlines
    ? /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g
    : /[\u0000-\u001F\u007F]/g;
  return str.replace(re, "");
}

// ============================
// Sanitizers (SRP: one per field)
// ============================

function sanitizeName(input) {
  let s = normalizeUnicode(input);
  s = stripControls(s);
  s = s.replace(/[^\p{L}\s'-]/gu, "");
  s = s.replace(/\s{2,}/g, " ").trim();
  return s.slice(0, 80);
}

function sanitizeEmail(input) {
  let s = normalizeUnicode(input).trim().toLowerCase();
  s = stripControls(s);
  s = s.replace(/[^a-z0-9._%+\-@]/g, "");
  const parts = s.split("@");
  if (parts.length > 2) s = parts.slice(0, 2).join("@");
  return s.slice(0, 254);
}

function sanitizePhone(input) {
  let s = normalizeUnicode(input);
  s = stripControls(s);
  s = s.replace(/[^\d+]/g, "");
  s = s.replace(/(?!^)\+/g, "");
  s = s.replace(/^\+?0+/, (m) => (m.startsWith("+") ? "+" : ""));
  return s.slice(0, 16);
}

function sanitizeMessage(input) {
  let s = normalizeUnicode(input);
  s = stripControls(s, { keepNewlines: true });
  s = s.replace(/<[^>]*>/g, "");
  s = s.replace(/[<>]/g, "");
  s = s.replace(/\/\*[\s\S]*?\*\//g, "");
  s = s.replace(/--/g, "");
  s = s.replace(/;/g, "");
  s = s.replace(/['"`\\]/g, "");
  s = s.replace(/[{}$]/g, "");
  s = s.replace(/\bjavascript\s*:/gi, "");
  s = s.replace(/[ \t]{2,}/g, " ").trim();
  return s.slice(0, 2000);
}

function sanitizeInput(input) {
  return sanitizeMessage(input);
}

// ============================
// Validators (SRP - one task each)
// ============================
function isNotEmpty(value) {
  return value.length > 0;
}

function isValidEmail(email) {
  const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return regex.test(email);
}

function isValidPhone(phone) {
  const regex = /^\+?\d{8,15}$/;
  return regex.test(phone);
}

function isValidMessage(message) {
  return message.length >= 5;
}

// ============================
// Error + Alert Handling
// ============================
function showError(inputElement, message) {
  inputElement.classList.add("error");
  showFormAlert("error", message);
}

function clearError(inputElement) {
  inputElement.classList.remove("error");
}

function showFormAlert(type, message) {
  const alertBox = document.getElementById("formAlert");
  const alertMessage = document.getElementById("formAlertMessage");
  if (!alertBox || !alertMessage) return;

  alertMessage.textContent = message;
  alertBox.className = `form-alert ${type}`;
  alertBox.classList.remove("hidden");

  window.clearTimeout(showFormAlert._t);
  showFormAlert._t = window.setTimeout(hideFormAlert, 10000);
}

function hideFormAlert() {
  const alertBox = document.getElementById("formAlert");
  if (alertBox) alertBox.classList.add("hidden");
}

function clearFormFields(nameInput, emailInput, phoneInput, messageInput) {
  nameInput.value = "";
  emailInput.value = "";
  phoneInput.value = "";
  messageInput.value = "";
}

const alertCloseBtn = document.getElementById("formAlertClose");
if (alertCloseBtn) alertCloseBtn.addEventListener("click", hideFormAlert);

// ============================
// Email Service (SRP: só envia email)
// ============================
class EmailService {
  constructor(serviceId, templateId, publicKey) {
    this.serviceId = serviceId;
    this.templateId = templateId;
    this.publicKey = publicKey;
    emailjs.init(this.publicKey);
  }

  async sendEmail({ name, email, phone, message }) {
    const templateParams = {
      name,
      email,
      phone: phone,
      timestamp: new Date().toLocaleString("pt-BR"),
      message: message,
    };

    try {
      const response = await emailjs.send(
        this.serviceId,
        this.templateId,
        templateParams
      );
      return { success: true, response };
    } catch (error) {
      console.error("Erro ao enviar email:", error);
      return { success: false, error };
    }
  }
}

// ============================
// Form Handler (SRP: valida + chama serviços)
// ============================
async function handleFormSubmit(event) {
  event.preventDefault();

  const nameInput = document.getElementById("nome");
  const emailInput = document.getElementById("email");
  const phoneInput = document.getElementById("tel");
  const messageInput = document.getElementById("msg");

  const name = sanitizeName(nameInput.value);
  const email = sanitizeEmail(emailInput.value);
  const phone = sanitizePhone(phoneInput.value);
  const message = sanitizeMessage(messageInput.value);

  nameInput.value = name;
  emailInput.value = email;
  phoneInput.value = phone;
  messageInput.value = message;

  let isValid = true;

  if (!isNotEmpty(name)) {
    showError(nameInput, "O nome é obrigatório.");
    isValid = false;
  } else clearError(nameInput);

  if (!isValidEmail(email)) {
    showError(emailInput, "Formato de e-mail inválido.");
    isValid = false;
  } else clearError(emailInput);

  if (!isValidPhone(phone)) {
    showError(
      phoneInput,
      "O telefone deve conter apenas números (8 a 15 dígitos)."
    );
    isValid = false;
  } else clearError(phoneInput);

  if (!isValidMessage(message)) {
    showError(messageInput, "A mensagem deve ter pelo menos 5 caracteres.");
    isValid = false;
  } else clearError(messageInput);

  if (!isValid) return;

  const emailService = new EmailService(
    "service_yq8he0m",
    "template_ciu2478",
    "K2JLEx06aJ9iVaPlK"
  );

  const result = await emailService.sendEmail({
    name,
    email,
    phone,
    message,
  });
  console.log(result);

  if (result.success) {
    clearFormFields(nameInput, emailInput, phoneInput, messageInput);
    showFormAlert("success", "Formulário enviado com sucesso!");
  } else {
    showFormAlert(
      "error",
      "Falha ao enviar mensagem. Tente novamente mais tarde."
    );
  }
}

// ============================
// Init
// ============================
document.getElementById("send").addEventListener("click", handleFormSubmit);

// ============================
// terms
// ============================