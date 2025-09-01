const API_BASE = '/api/admin/articles';
const USERS_API = '/api/admin/users';

// ================= CHARGEMENT DES DONNÉES =================
async function loadArticles(){
    try {
        setLoading(true);
        const res = await fetch(API_BASE, { headers: authHeaders() });
        if(!res.ok) throw new Error('Impossible de charger les articles');
        articles = await res.json();
        articles = articles.map(a => ({ ...a, id: a.id || a._id || a.code }));

        const units = new Set();
        const types = new Set();
        const demars = new Set();

        articles.forEach(item => {
            if (item.unite) units.add(item.unite);
            if (item.type) types.add(item.type);
            if (item.demar) demars.add(item.demar);
        });

        allUnits = Array.from(units);
        allTypes = Array.from(types);
        allDemars = Array.from(demars);

        updateFilterOptions();
        applyFiltersSortSearch();
        toast('Articles chargés avec succès');
    } catch (e){
        console.error(e);
        toast('Erreur chargement articles: ' + e.message, 'err');
    } finally {
        setLoading(false);
    }
}

async function loadUsers() {
    try {
        const res = await fetch(USERS_API, { headers: authHeaders() });
        if (!res.ok) throw new Error('Impossible de charger les utilisateurs');
        users = await res.json();
        renderUsersTable();
    } catch (e) {
        console.error(e);
        toast('Erreur chargement utilisateurs: ' + e.message, 'err');
    }
}

async function saveArticle(data, id){
    try {
        const method = id ? 'PUT' : 'POST';
        const url = id ? `${API_BASE}/${id}` : API_BASE;
        const res = await fetch(url, {
            method,
            headers: authHeaders(),
            body: JSON.stringify(data)
        });
        if(!res.ok){
            const txt = await res.text();
            throw new Error(txt || 'Erreur sauvegarde');
        }
        toast('Article enregistré');
        closeModal('addArticleModal');
        await loadArticles();
    } catch (e){
        console.error(e);
        toast('Erreur enregistrement: ' + e.message, 'err');
        throw e;
    }
}

async function deleteArticle(id){
    if(!confirm('Supprimer cet article ?')) return;
    try {
        const res = await fetch(`${API_BASE}/${id}`, { method:'DELETE', headers: authHeaders() });
        if(!res.ok) throw new Error('Erreur suppression');
        toast('Article supprimé');
        await loadArticles();
    } catch (e){
        console.error(e);
        toast('Erreur suppression: ' + e.message, 'err');
    }
}

async function saveUser(userData, id) {
    try {
        const method = id ? 'PUT' : 'POST';
        const url = id ? `${USERS_API}/${id}` : USERS_API;
        const res = await fetch(url, {
            method,
            headers: authHeaders(),
            body: JSON.stringify(userData)
        });
        if (!res.ok) throw new Error('Erreur sauvegarde');
        toast('Utilisateur enregistré');
        closeModal('userModal');
        loadUsers();
    } catch (e) {
        toast('Erreur: ' + e.message, 'err');
    }
}

async function getUserById(id) {
    const res = await fetch(`${USERS_API}/${id}`, { headers: authHeaders() });
    if (!res.ok) throw new Error('Utilisateur non trouvé');
    return await res.json();
}

async function deleteUser(id) {
    if (!confirm('Supprimer cet utilisateur ?')) return;
    try {
        const res = await fetch(`${USERS_API}/${id}`, { method: 'DELETE', headers: authHeaders() });
        if (!res.ok) throw new Error('Erreur suppression');
        toast('Utilisateur supprimé');
        loadUsers();
    } catch (e) {
        toast('Erreur suppression: ' + e.message, 'err');
    }
}
