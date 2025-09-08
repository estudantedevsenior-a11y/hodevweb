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

let acceptTerms = false

function terms() {
  return `
    <div class="lgpd-overlay" role="dialog" aria-modal="true" aria-labelledby="lgpdTitle">
      <style>
        .lgpd-overlay{position:fixed;inset:0;background:rgba(2,6,23,0.55);display:flex;align-items:center;justify-content:center;z-index:9999}
        .lgpd-modal{width:min(760px,94vw);background:#fff;border-radius:12px;padding:18px;box-shadow:0 10px 40px rgba(2,6,23,0.35);max-height:86vh;overflow:auto;font-family:Arial,sans-serif;color:#1f2937}
        .lgpd-header{display:flex;gap:12px;align-items:center}
        .lgpd-title{font-size:18px;font-weight:700}
        .lgpd-body{margin-top:10px}
        .lgpd-points{margin:12px 0;padding-left:18px;color:#6b7280}
        .lgpd-actions{display:flex;gap:10px;justify-content:flex-end;margin-top:16px}
        .lgpd-check{display:flex;align-items:center;gap:8px;margin-top:12px}
        .link{color:#1B65A6;text-decoration:none}
        button.lgpd-btn{padding:8px 12px;border-radius:8px;border:0;cursor:pointer;font-size:14px}
        button.lgpd-decline{background:transparent;color:#374151}
        button.lgpd-accept{background:#1B65A6;color:#fff}
        button.lgpd-accept[disabled]{opacity:0.6;cursor:not-allowed}
      </style>

      <div class="lgpd-modal">
        <div class="lgpd-header">
          <div style="width:44px;height:44px;background:linear-gradient(180deg,#1B65A6,#145085);border-radius:10px;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700">HW</div>
          <div>
            <div id="lgpdTitle" class="lgpd-title">Termos de Uso e Tratamento de Dados (LGPD)</div>
            <div style="font-size:13px;color:#6b7280">hodevweb.com.br — coleta limitada para contato futuro</div>
          </div>
        </div>

        <div class="lgpd-body">
          <p>Ao aceitar, você concorda que os dados que fornecer no formulário de contato (nome, e-mail e mensagem) serão armazenados e utilizados apenas para fins de comunicação futura relacionada ao seu contato. Esta base legal fundamenta-se no <strong>consentimento</strong> (Art. 7º, LGPD).</p>

          <ul class="lgpd-points">
            <li><strong>Finalidade:</strong> responder seu contato e enviar comunicações relacionadas.</li>
            <li><strong>Limitação:</strong> apenas dados do formulário serão captados.</li>
            <li><strong>Retenção:</strong> guardaremos seus dados pelo tempo necessário.</li>
            <li><strong>Seus direitos:</strong> acesso, correção, exclusão, revogação do consentimento — contate <a class="link" href="mailto:privacy@hodevweb.com.br">privacy@hodevweb.com.br</a>.</li>
          </ul>

          <div class="lgpd-check">
            <input type="checkbox" id="lgpdAcceptCheck">
            <label for="lgpdAcceptCheck" style="margin:0">Eu li e aceito que meus dados sejam usados conforme descrito acima.</label>
          </div>

          <div style="margin-top:10px;font-size:13px;color:#374151">
            <small>Mais detalhes em <a class="link" href="https://www.hodevweb.com.br/" target="_blank" rel="noopener">hodevweb.com.br</a>. Você pode revogar o consentimento a qualquer momento.</small>
          </div>
        </div>

        <div class="lgpd-actions">
          <button id="lgpdDecline" class="lgpd-btn lgpd-decline" type="button">Recusar</button>
          <button id="lgpdAccept" class="lgpd-btn lgpd-accept" type="button" disabled>Aceitar e salvar</button>
        </div>
      </div>
    </div>
  `;
}

// https://chatgpt.com/share/68bf0ce5-2490-800c-aa45-3c78e62e5228
function openTerms() {
  const wrapper = document.createElement("div");
  wrapper.innerHTML = terms();
  wrapper.id = "terms-modal";
  document.body.appendChild(wrapper);

  // agora adiciona os eventos
  wrapper.querySelector("#lgpdDecline").addEventListener("click", closeTerms);
  wrapper.querySelector("#lgpdAccept").addEventListener("click", closeTerms);
}

function closeTerms(event) {
  console.log("Fechando modal via:", event.target.id);
  document.getElementById("terms-modal")?.remove();
}


function acceptedOrNotTerms() { }