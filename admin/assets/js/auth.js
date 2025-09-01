// ================= AUTHENTIFICATION =================
async function checkAuth() {
    try {
        const res = await fetch('/api/auth/verify');
        if (!res.ok) {
            showLogin();
            return;
        }
        const data = await res.json();
        currentUser = data.user;
        updateWelcomeMessage();
        showDashboard();
        checkUserPermissions();
    } catch (e) {
        showLogin();
    }
}

// Mise à jour du message de bienvenue selon l'heure
function updateWelcomeMessage() {
    const hour = new Date().getHours();
    let greeting;

    if (hour >= 5 && hour < 12) {
        greeting = 'Bonjour';
    } else if (hour >= 12 && hour < 18) {
        greeting = 'Bonsoir';
    } else {
        greeting = 'Bonne nuit';
    }

    document.getElementById('welcome-message').innerHTML = `${greeting}, <strong>${currentUser.name || currentUser.username || 'Administrateur'}</strong>`;
}

// Afficher l'onglet utilisateurs seulement pour les administrateurs
function checkUserPermissions() {
    if (currentUser && currentUser.role === 'admin') {
        document.getElementById('users-tab').style.display = 'block';
    } else {
        document.getElementById('users-tab').style.display = 'none';
    }
}

// Afficher la page de connexion
function showLogin() {
    document.getElementById('login-page').style.display = 'flex';
    document.getElementById('dashboard-page').classList.remove('active');
}

// Afficher le dashboard
function showDashboard() {
    document.getElementById('login-page').style.display = 'none';
    document.getElementById('dashboard-page').classList.add('active');
    loadArticles();
}

async function logout() {
    if (confirm('Êtes-vous sûr de vouloir vous déconnecter ?')) {
        try {
            await fetch('/api/auth/logout', { method: 'POST' });
        } catch (e) {
            console.error('Erreur lors de la déconnexion', e);
        } finally {
            currentUser = null;
            toast('Déconnexion réussie.');
            // Recharger la page pour afficher l'écran de connexion
            window.location.reload();
        }
    }
}

function authHeaders() {
    return {
        'Content-Type': 'application/json'
    };
}
