// ================= GESTION DU THÈME =================
function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);

    const icon = document.getElementById('theme-icon');
    icon.className = newTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
}

// Charger le thème sauvegardé
function loadTheme() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);

    const icon = document.getElementById('theme-icon');
    if (icon) {
        icon.className = savedTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }
}

// ================= GESTION DES STATISTIQUES =================
function toggleStats() {
    const statsGrid = document.getElementById('stats-grid');
    const toggleBtn = document.getElementById('stats-toggle-btn');
    const eyeIcon = document.getElementById('stats-eye-icon');
    const toggleText = document.getElementById('stats-toggle-text');

    statsVisible = !statsVisible;

    if (statsVisible) {
        statsGrid.classList.remove('hidden');
        eyeIcon.className = 'fas fa-eye';
        toggleText.textContent = 'Masquer les statistiques';
    } else {
        statsGrid.classList.add('hidden');
        eyeIcon.className = 'fas fa-eye-slash';
        toggleText.textContent = 'Afficher les statistiques';
    }

    localStorage.setItem('statsVisible', statsVisible);
}

// ================= UTILS =================
function toast(message, type='success', timeout=3500){
    const el = document.createElement('div');
    el.className = 'toast ' + (type === 'success' ? '' : (type === 'err' ? 'err' : 'warn'));
    el.innerHTML = `
        <i class="fas ${type === 'success' ? 'fa-check-circle' : type === 'err' ? 'fa-exclamation-circle' : 'fa-exclamation-triangle'}"></i>
        <div style="flex:1">${message}</div>
        <button style="background:transparent;border:none;color:var(--text-secondary);cursor:pointer" onclick="this.closest('.toast').remove()">
            <i class="fas fa-times"></i>
        </button>
    `;

    let toastContainer = document.getElementById('toasts');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toasts';
        toastContainer.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 10000;
            display: flex;
            flex-direction: column;
            gap: 10px;
        `;
        document.body.appendChild(toastContainer);
    }

    toastContainer.appendChild(el);
    if(timeout) setTimeout(()=> el.remove(), timeout);
}

function formatCurrency(v) {
    if (v === null || v === undefined || isNaN(v)) return '';
    return Number(v).toLocaleString('fr-FR', {minimumFractionDigits:2, maximumFractionDigits:2});
}

function setLoading(loading) {
    isLoading = loading;
    const tbody = document.getElementById('articles-tbody');
    const cardsContainer = document.getElementById('articles-cards');
    if (loading) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" style="text-align:center;padding:40px;color:var(--text-secondary)">
                    <div style="font-size:24px;margin-bottom:16px">⏳</div>
                    <div>Chargement des articles...</div>
                </td>
            </tr>
        `;
        cardsContainer.innerHTML = `
            <div class="loading">
                <div>Chargement des articles...</div>
            </div>
        `;
    }
}

function escapeHtml(s){
    if(s === null || s === undefined) return '';
    return String(s)
        .replaceAll('&','&amp;')
        .replaceAll('<','&lt;')
        .replaceAll('>','&gt;')
        .replaceAll('"','&quot;');
}

// ================= RENDERING =================
function renderTable(list = filtered) {
    const tbody = document.getElementById('articles-tbody');
    tbody.innerHTML = '';

    if(!list.length){
        tbody.innerHTML = `
            <tr>
                <td colspan="9" style="text-align:center;padding:40px;color:var(--text-secondary)">
                    <div style="font-size:48px;margin-bottom:16px;opacity:0.3">📦</div>
                    <div>Aucun article trouvé</div>
                </td>
            </tr>
        `;
        return;
    }

    list.forEach(a => {
        const valeur = (Number(a.prix_vente) || 0) * (Number(a.achat_minimum) || 0);
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>
                <div class="action-buttons">
                    <button class="btn-icon btn-edit" onclick="openEdit('${a.id}')" title="Modifier">
                        <svg class="icon-edit" viewBox="0 0 24 24" fill="currentColor">
                            <path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/>
                        </svg>
                    </button>
                    <button class="btn-icon btn-delete" onclick="deleteArticle('${a.id}')" title="Supprimer">
                        <svg class="icon-delete" viewBox="0 0 24 24" fill="currentColor">
                            <path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/>
                        </svg>
                    </button>
                </div>
            </td>
            <td>${escapeHtml(a.code || '')}</td>
            <td>${escapeHtml(a.description || '')}</td>
            <td>${escapeHtml(a.demar || '')}</td>
            <td>$${formatCurrency(a.prix_vente)}</td>
            <td>${Number(a.achat_minimum) || 0}</td>
            <td class="value-column">$${formatCurrency(valeur)}</td>
            <td>${escapeHtml(a.unite || '')}</td>
            <td>${escapeHtml(a.type || '')}</td>
        `;
        tbody.appendChild(tr);
    });

    renderCards(list);
}

function renderCards(list = filtered) {
    const cardsContainer = document.getElementById('articles-cards');
    cardsContainer.innerHTML = '';

    if(!list.length){
        cardsContainer.innerHTML = `
            <div class="empty-state">
                <div style="font-size:48px;margin-bottom:16px;opacity:0.3">📦</div>
                <h3>Aucun article trouvé</h3>
                <p>Essayez de modifier vos filtres ou votre recherche</p>
            </div>
        `;
        return;
    }

    list.forEach(a => {
        const valeur = (Number(a.prix_vente) || 0) * (Number(a.achat_minimum) || 0);
        const card = document.createElement('div');
        card.className = 'article-card';

        const demarClass = (a.demar || '').toLowerCase() === 'oui' ? 'demar' : 'demar non';

        card.innerHTML = `
            <div class="card-header">
                <div class="card-title">
                    <div class="card-code">${escapeHtml(a.code || '')}</div>
                    <div class="card-description">${escapeHtml(a.description || '')}</div>
                </div>
                <div class="card-actions">
                    <button class="btn-icon btn-edit" onclick="openEdit('${a.id}')" title="Modifier">
                        <svg class="icon-edit" viewBox="0 0 24 24" fill="currentColor">
                            <path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/>
                        </svg>
                    </button>
                    <button class="btn-icon btn-delete" onclick="deleteArticle('${a.id}')" title="Supprimer">
                        <svg class="icon-delete" viewBox="0 0 24 24" fill="currentColor">
                            <path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/>
                        </svg>
                    </button>
                </div>
            </div>
            <div class="card-info-grid">
                <div class="card-info-item">
                    <span class="card-info-label">Prix ($)</span>
                    <span class="card-info-value price">$${formatCurrency(a.prix_vente)}</span>
                </div>
                <div class="card-info-item">
                    <span class="card-info-label">Achat Min</span>
                    <span class="card-info-value">${Number(a.achat_minimum) || 0}</span>
                </div>
                <div class="card-info-item">
                    <span class="card-info-label">Valeur ($)</span>
                    <span class="card-info-value value">$${formatCurrency(valeur)}</span>
                </div>
                <div class="card-info-item">
                    <span class="card-info-label">Unité</span>
                    <span class="card-info-value">${escapeHtml(a.unite || '')}</span>
                </div>
            </div>
            <div class="card-footer">
                <div class="card-tags">
                    <span class="card-tag type">${escapeHtml(a.type || 'divers')}</span>
                    <span class="card-tag ${demarClass}">Demar: ${escapeHtml(a.demar || 'Non')}</span>
                </div>
            </div>
        `;
        cardsContainer.appendChild(card);
    });
}

// ================= NAVIGATION ENTRE ONGLETS =================
function switchTab(tab) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelector(`[onclick="switchTab('${tab}')"]`).classList.add('active');

    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById(`${tab}-view`).classList.add('active');

    let subtitle;
    switch(tab) {
        case 'articles':
            subtitle = 'Gestion des Articles & Prix';
            break;
        case 'batch':
            subtitle = 'Ajout d\'Articles en Lot';
            break;
        case 'users':
            subtitle = 'Gestion des Utilisateurs';
            break;
        default:
            subtitle = 'Tableau de bord';
    }
    document.getElementById('subtitle').textContent = subtitle;

    currentTab = tab;

    if (tab === 'batch') {
        initBatchTable();
    } else if (tab === 'users') {
        loadUsers();
    }
}

// ================= GESTION DES MODALES =================
function openAddArticleModal() {
    document.getElementById('addArticleModal').classList.add('active');
}

function closeModal(modalId) {
    document.getElementById(modalId).classList.remove('active');
    const form = document.querySelector(`#${modalId} form`);
    if (form) form.reset();

    if (modalId === 'addArticleModal') {
        closeArticleModal();
    }
}

function showArticleModal(){
    document.getElementById('addArticleModal').classList.add('active');
    document.getElementById('article-price').addEventListener('input', calculateValue);
    document.getElementById('article-achat').addEventListener('input', calculateValue);
    updateSuggestions();
}

function updateSuggestions() {
    const unitSuggestions = document.getElementById('unit-suggestions');
    if (unitSuggestions) {
        unitSuggestions.innerHTML = '';
        allUnits.forEach(unit => {
            const option = document.createElement('option');
            option.value = unit;
            unitSuggestions.appendChild(option);
        });
    }

    const typeSuggestions = document.getElementById('type-suggestions');
    if (typeSuggestions) {
        typeSuggestions.innerHTML = '';
        allTypes.forEach(type => {
            const option = document.createElement('option');
            option.value = type;
            typeSuggestions.appendChild(option);
        });
    }

    const demarSuggestions = document.getElementById('demar-suggestions');
    if (demarSuggestions) {
        demarSuggestions.innerHTML = '';
        allDemars.forEach(demar => {
            const option = document.createElement('option');
            option.value = demar;
            demarSuggestions.appendChild(option);
        });
    }
}

function calculateValue() {
    const prix = parseFloat(document.getElementById('article-price').value) || 0;
    const achat = parseInt(document.getElementById('article-achat').value) || 0;
    const valeur = prix * achat;
    document.getElementById('article-value').value = formatCurrency(valeur);
}

function closeArticleModal(){
    document.getElementById('addArticleModal').classList.remove('active');
    document.getElementById('article-price').removeEventListener('input', calculateValue);
    document.getElementById('article-achat').removeEventListener('input', calculateValue);
}

function toggleValueColumn() {
    const valueColumns = document.querySelectorAll('.value-column');
    const toggleBtn = document.getElementById('toggle-value-btn');

    valueColumns.forEach(col => {
        if (col.style.display === 'none') {
            col.style.display = '';
            toggleBtn.innerHTML = '<i class="fas fa-eye mr-1"></i>Valeur';
            toggleBtn.title = 'Masquer la colonne Valeur';
        } else {
            col.style.display = 'none';
            toggleBtn.innerHTML = '<i class="fas fa-eye-slash mr-1"></i>Valeur';
            toggleBtn.title = 'Afficher la colonne Valeur';
        }
    });
}
