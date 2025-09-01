/* ================= FILTRES, TRI ET RECHERCHE ================= */
function applyFiltersSortSearch() {
    const searchInput = document.getElementById('search-articles');
    const typeFilter = document.getElementById('filter-type');
    const demarFilter = document.getElementById('filter-demar');

    if (!searchInput || !typeFilter || !demarFilter) return;

    const searchTerm = searchInput.value.toLowerCase();
    const typeFilterValue = typeFilter.value;
    const demarFilterValue = demarFilter.value;

    filtered = articles.filter(article => {
        const matchesSearch = (article.code || '').toLowerCase().includes(searchTerm) ||
                            (article.description || '').toLowerCase().includes(searchTerm) ||
                            (article.type || '').toLowerCase().includes(searchTerm) ||
                            (article.demar || '').toLowerCase().includes(searchTerm);

        const matchesType = !typeFilterValue || article.type === typeFilterValue;
        const matchesDemar = !demarFilterValue || (article.demar || '').toLowerCase() === demarFilterValue.toLowerCase();

        return matchesSearch && matchesType && matchesDemar;
    });

    if (sortState.key) {
        applySorting();
    }

    updateStats();
    renderTable();
}

function applySorting() {
    const { key, dir } = sortState;

    filtered.sort((a, b) => {
        let aVal = a[key];
        let bVal = b[key];

        if (key === 'prix_vente' || key === 'achat_minimum' || key === 'price' || key === 'achat') {
            aVal = Number(aVal) || 0;
            bVal = Number(bVal) || 0;
        } else if (key === 'value') {
            aVal = (Number(a.prix_vente) || 0) * (Number(a.achat_minimum) || 0);
            bVal = (Number(b.prix_vente) || 0) * (Number(b.achat_minimum) || 0);
        } else if (typeof aVal === 'string') {
            aVal = aVal.toLowerCase();
            bVal = (bVal || '').toLowerCase();
        }

        if (aVal < bVal) return -1 * dir;
        if (aVal > bVal) return 1 * dir;
        return 0;
    });
}

function filterArticles() {
    applyFiltersSortSearch();
}

function sortTable(column) {
    const direction = sortState.key === column && sortState.dir === 1 ? -1 : 1;
    sortState = { key: column, dir: direction };
    applyFiltersSortSearch();
}

/* ================= CRUD ARTICLES ================= */
function validateArticleForm(){
    const code = document.getElementById('article-code').value.trim();
    const desc = document.getElementById('article-description').value.trim();
    const prix = document.getElementById('article-price').value;

    let ok = true;

    document.getElementById('article-code').style.borderColor = '';
    document.getElementById('article-description').style.borderColor = '';
    document.getElementById('article-price').style.borderColor = '';

    if(!code){
        document.getElementById('article-code').style.borderColor = 'var(--danger-color)';
        ok = false;
    }
    if(!desc){
        document.getElementById('article-description').style.borderColor = 'var(--danger-color)';
        ok = false;
    }
    if(prix === '' || isNaN(prix)){
        document.getElementById('article-price').style.borderColor = 'var(--danger-color)';
        ok = false;
    }

    const id = document.getElementById('articleId') ? document.getElementById('articleId').value : '';
    const dup = articles.find(a => a.code && a.code.toLowerCase() === code.toLowerCase() && String(a.id) !== String(id));
    if(dup){
        document.getElementById('article-code').style.borderColor = 'var(--danger-color)';
        toast('Code dupliqué détecté: ' + dup.code, 'err');
        ok = false;
    }

    return ok;
}

async function handleAddArticle(e) {
    e.preventDefault();

    if (!validateArticleForm()) {
        return;
    }

    const articleId = document.getElementById('articleId') ? document.getElementById('articleId').value : '';
    const newArticle = {
        code: document.getElementById('article-code').value,
        description: document.getElementById('article-description').value,
        prix_vente: parseFloat(document.getElementById('article-price').value),
        achat_minimum: parseInt(document.getElementById('article-achat').value),
        unite: document.getElementById('article-unit').value || 'Unité',
        type: document.getElementById('article-type').value || 'divers',
        demar: document.getElementById('article-demar').value || 'Non'
    };

    await saveArticle(newArticle, articleId);
}

function openAdd(){
    document.getElementById('modalTitle').textContent = 'Ajouter un article';
    if (document.getElementById('articleId')) document.getElementById('articleId').value = '';
    document.getElementById('article-code').value = '';
    document.getElementById('article-type').value = '';
    document.getElementById('article-description').value = '';
    document.getElementById('article-price').value = '';
    document.getElementById('article-achat').value = '';
    document.getElementById('article-value').value = '';
    document.getElementById('article-unit').value = '';
    document.getElementById('article-demar').value = '';
    showArticleModal();
}

function openEdit(id){
    const a = articles.find(x => String(x.id) === String(id));
    if(!a){ toast('Article introuvable','err'); return; }

    document.getElementById('modalTitle').textContent = 'Modifier un article';
    document.getElementById('articleId').value = a.id;
    document.getElementById('article-code').value = a.code || '';
    document.getElementById('article-type').value = a.type || '';
    document.getElementById('article-description').value = a.description || '';
    document.getElementById('article-price').value = a.prix_vente || '';
    document.getElementById('article-achat').value = a.achat_minimum || '';

    const prix = Number(a.prix_vente) || 0;
    const achat = Number(a.achat_minimum) || 0;
    document.getElementById('article-value').value = formatCurrency(prix * achat);

    document.getElementById('article-unit').value = a.unite || '';
    document.getElementById('article-demar').value = a.demar || '';

    showArticleModal();
}

/* ================= AJOUT EN LOT ================= */
function initBatchTable() {
    const tableBody = document.getElementById('batch-items-table');
    if (!tableBody) return;

    tableBody.innerHTML = '';

    for (let i = 0; i < 5; i++) {
        addBatchRow();
    }

    const addRowBtn = document.getElementById('batch-add-row');
    const saveAllBtn = document.getElementById('batch-save-all');

    if (addRowBtn) {
        addRowBtn.removeEventListener('click', addBatchRow);
        addRowBtn.addEventListener('click', addBatchRow);
    }

    if (saveAllBtn) {
        saveAllBtn.removeEventListener('click', saveBatchData);
        saveAllBtn.addEventListener('click', saveBatchData);
    }
}

function addBatchRow() {
    const tableBody = document.getElementById('batch-items-table');
    if (!tableBody) return;

    const newRow = document.createElement('tr');

    newRow.innerHTML = `
        <td><input type="text" class="batch-code" placeholder="Ex: W0110-F4-08" style="min-width: 120px;"></td>
        <td><input type="text" class="batch-desc" placeholder="Description" style="min-width: 150px;"></td>
        <td><input type="text" class="batch-demar" placeholder="0000" style="min-width: 80px;" list="demar-list"></td>
        <td><input type="number" step="0.01" min="0" class="batch-price" placeholder="0.00" style="min-width: 80px;"></td>
        <td><input type="number" step="1" min="0" class="batch-min" placeholder="0" style="min-width: 80px;"></td>
        <td><input type="text" class="batch-unit" placeholder="Unité" list="unit-list" style="min-width: 80px;"></td>
        <td><input type="text" class="batch-type" placeholder="Type" list="type-list" style="min-width: 100px;"></td>
        <td style="min-width: 60px;">
            <button type="button" class="btn-icon btn-delete remove-btn" title="Supprimer cette ligne">
                <svg class="icon-delete" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/>
                </svg>
            </button>
        </td>
    `;

    tableBody.appendChild(newRow);

    const removeBtn = newRow.querySelector('.remove-btn');
    removeBtn.addEventListener('click', function() {
        if (tableBody.querySelectorAll('tr').length > 1) {
            tableBody.removeChild(newRow);
        } else {
            toast('Vous devez conserver au moins une ligne', 'warn');
        }
    });

    setupKeyboardNavigation(newRow);

    newRow.querySelector('.batch-code').focus();
}

function setupKeyboardNavigation(row) {
    const inputs = row.querySelectorAll('input');

    inputs.forEach((input, index) => {
        input.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();

                if (index === inputs.length - 1) {
                    addBatchRow();
                } else {
                    inputs[index + 1].focus();
                }
            } else if (e.key === 'Tab' && !e.shiftKey && index === inputs.length - 1) {
                e.preventDefault();
                addBatchRow();
            }
        });
    });
}

async function saveBatchData() {
    const rows = document.querySelectorAll('#batch-items-table tr');
    let isValid = true;
    const items = [];
    const newUnits = [];
    const newTypes = [];

    rows.forEach((row, index) => {
        const code = row.querySelector('.batch-code').value.trim();
        const description = row.querySelector('.batch-desc').value.trim();
        const demar = row.querySelector('.batch-demar').value.trim();
        const price = row.querySelector('.batch-price').value;
        const min = row.querySelector('.batch-min').value;
        const unit = row.querySelector('.batch-unit').value.trim();
        const type = row.querySelector('.batch-type').value.trim();

        row.querySelector('.batch-code').style.borderColor = '';
        row.querySelector('.batch-desc').style.borderColor = '';

        if (code || description) {
            if (!code || !description) {
                isValid = false;
                if (!code) row.querySelector('.batch-code').style.borderColor = 'var(--danger-color)';
                if (!description) row.querySelector('.batch-desc').style.borderColor = 'var(--danger-color)';
            } else {
                const duplicate = items.find(item => item.code.toLowerCase() === code.toLowerCase());
                if (duplicate) {
                    toast(`Ligne ${index + 1}: Code dupliqué dans le lot: ${code}`, 'err');
                    row.querySelector('.batch-code').style.borderColor = 'var(--danger-color)';
                    isValid = false;
                    return;
                }

                const existingDup = articles.find(a => a.code && a.code.toLowerCase() === code.toLowerCase());
                if (existingDup) {
                    toast(`Ligne ${index + 1}: Code déjà existant: ${code}`, 'err');
                    row.querySelector('.batch-code').style.borderColor = 'var(--danger-color)';
                    isValid = false;
                    return;
                }

                const item = {
                    code,
                    description,
                    demar: demar || 'Non',
                    prix_vente: price ? parseFloat(price) : 0,
                    achat_minimum: min ? parseInt(min) : 0,
                    unite: unit || 'Unité',
                    type: type || 'divers'
                };
                items.push(item);

                if (unit && !allUnits.includes(unit)) {
                    newUnits.push(unit);
                }
                if (type && !allTypes.includes(type)) {
                    newTypes.push(type);
                }
            }
        }
    });

    if (!isValid) {
        toast('Veuillez remplir les champs obligatoires (CODE et DESCRIPTION) pour toutes les lignes non vides', 'err');
        return;
    }

    if (items.length === 0) {
        toast('Aucun article valide à sauvegarder', 'warn');
        return;
    }

    try {
        let savedCount = 0;
        for (const item of items) {
            try {
                await saveArticle(item);
                savedCount++;
            } catch (error) {
                console.error('Erreur sauvegarde article:', item.code, error);
            }
        }

        allUnits.push(...newUnits);
        allTypes.push(...newTypes);

        toast(`${savedCount} articles ajoutés avec succès !`);

        clearBatchTable();
        switchTab('articles');
        await loadArticles();
    } catch (error) {
        toast('Erreur lors de la sauvegarde en lot: ' + error.message, 'err');
    }
}

function clearBatchTable() {
    const tableBody = document.getElementById('batch-items-table');
    if (tableBody) {
        tableBody.innerHTML = '';
        for (let i = 0; i < 3; i++) {
            addBatchRow();
        }
    }
}

/* ================= EXPORT EXCEL ================= */
function exportFilteredToExcel(){
    if(!filtered.length){
        toast('Aucune donnée à exporter','warn');
        return;
    }

    const data = filtered.map(a => ({
        Code: a.code,
        Description: a.description,
        Demar: a.demar,
        'Prix Vente ($)': a.prix_vente,
        'Achat Minimum': a.achat_minimum,
        'Valeur ($)': (Number(a.prix_vente) || 0) * (Number(a.achat_minimum) || 0),
        Unite: a.unite,
        Type: a.type,
        'ID': a.id
    }));

    try {
        if (typeof XLSX !== 'undefined') {
            const wb = XLSX.utils.book_new();
            const ws = XLSX.utils.json_to_sheet(data);
            XLSX.utils.book_append_sheet(wb, ws, 'Articles');
            XLSX.writeFile(wb, `articles_export_${new Date().toISOString().split('T')[0]}.xlsx`);
        } else {
            const csvContent = [
                Object.keys(data[0]).join(','),
                ...data.map(row => Object.values(row).map(val => `"${val}"`).join(','))
            ].join('\n');

            const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            link.setAttribute('href', url);
            link.setAttribute('download', `articles_export_${new Date().toISOString().split('T')[0]}.csv`);
            link.style.visibility = 'hidden';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }

        toast('Export terminé avec succès');
    } catch (error) {
        console.error('Erreur export:', error);
        toast('Erreur lors de l\'export', 'err');
    }
}

/* ================= ACTIONS DIVERSES ================= */
function exportArticles() {
    exportFilteredToExcel();
}

function refreshArticles() {
    loadArticles();
}

function updateFilterOptions() {
    const typeSelect = document.getElementById('filter-type');
    const demarSelect = document.getElementById('filter-demar');

    if (!typeSelect || !demarSelect) return;

    const currentType = typeSelect.value;
    const currentDemar = demarSelect.value;

    typeSelect.innerHTML = '<option value="">Filtrer par Type</option>';
    allTypes.forEach(type => {
        const option = document.createElement('option');
        option.value = type;
        option.textContent = type.charAt(0).toUpperCase() + type.slice(1);
        typeSelect.appendChild(option);
    });

    demarSelect.innerHTML = '<option value="">Filtrer par Demar.</option>';
    allDemars.forEach(demar => {
        const option = document.createElement('option');
        option.value = demar;
        option.textContent = demar;
        demarSelect.appendChild(option);
    });

    typeSelect.value = currentType;
    demarSelect.value = currentDemar;
}

function updateStats(){
    const count = filtered.length;
    const prixSum = filtered.reduce((s, a)=> s + (Number(a.prix_vente)||0), 0);
    const prixAvg = count ? (prixSum / count) : 0;

    const valeurSum = filtered.reduce((s, a)=> {
        const prix = Number(a.prix_vente) || 0;
        const achat = Number(a.achat_minimum) || 0;
        return s + (prix * achat);
    }, 0);

    const valeurAvg = count ? (valeurSum / count) : 0;

    document.getElementById('total-articles').textContent = count;
    document.getElementById('avg-price').textContent = count ? `$${formatCurrency(prixAvg)}` : '-';
    document.getElementById('total-value').textContent = `$${formatCurrency(valeurSum)}`;
    document.getElementById('avg-value').textContent = `$${formatCurrency(valeurAvg)}`;
}
