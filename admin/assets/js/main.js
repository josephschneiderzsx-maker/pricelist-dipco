function setupEventListeners() {
    // Charger le thème sauvegardé
    loadTheme();

    // Charger l'état des statistiques
    const savedStatsVisible = localStorage.getItem('statsVisible');
    if (savedStatsVisible !== null) {
        statsVisible = savedStatsVisible === 'true';
        if (!statsVisible) {
            document.getElementById('stats-grid').classList.add('hidden');
            document.getElementById('stats-eye-icon').className = 'fas fa-eye-slash';
            document.getElementById('stats-toggle-text').textContent = 'Afficher les statistiques';
        }
    }

    // Recherche en temps réel
    const searchInput = document.getElementById('search-articles');
    const typeFilter = document.getElementById('filter-type');
    const demarFilter = document.getElementById('filter-demar');

    if (searchInput) searchInput.addEventListener('input', applyFiltersSortSearch);
    if (typeFilter) typeFilter.addEventListener('change', applyFiltersSortSearch);
    if (demarFilter) demarFilter.addEventListener('change', applyFiltersSortSearch);

    // Formulaires
    const addArticleForm = document.getElementById('addArticleForm');
    if (addArticleForm) addArticleForm.addEventListener('submit', handleAddArticle);

    // Formulaire utilisateur
    const userForm = document.getElementById('userForm');
    if (userForm) userForm.addEventListener('submit', handleUserFormSubmit);

    // Fermeture des modales en cliquant à l'extérieur
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                closeModal(modal.id);
            }
        });
    });
}

// ================= STATE =================
let articles = [];
let users = [];
let filtered = [];
let sortState = { key: null, dir: 1 };
let allUnits = [];
let allTypes = [];
let allDemars = [];
let currentTab = 'articles';
let isLoading = false;
let statsVisible = true;
let currentUser = null;

// ================= INITIALISATION =================
document.addEventListener('DOMContentLoaded', function() {
    // Vérifier l'authentification
    checkAuth();

    // Configurer les écouteurs d'événements
    setupEventListeners();

    // Gestion du formulaire de connexion
    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();

        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value.trim();
        const errorDiv = document.getElementById('error-message');

        errorDiv.classList.add('hidden');

        try {
            const res = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            if (!res.ok) throw new Error('Identifiants incorrects');

            const data = await res.json();

            // La session est maintenant gérée par cookie httpOnly
            // Nous utilisons la réponse pour mettre à jour l'interface utilisateur
            currentUser = data.user;
            toast('Connexion réussie !');
            // Recharger la page pour que le serveur gère l'état de connexion
            window.location.reload();
        } catch (error) {
            errorDiv.textContent = error.message;
            errorDiv.classList.remove('hidden');
        }
    });

    // Démarrer l'auto-refresh
    startAutoRefresh();
});

window.addEventListener('beforeunload', stopAutoRefresh);
