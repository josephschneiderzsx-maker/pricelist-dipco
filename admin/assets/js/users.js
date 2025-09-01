// ================= GESTION DES UTILISATEURS =================
function renderUsersTable() {
    const tbody = document.getElementById('users-tbody');
    tbody.innerHTML = '';

    if (!users.length) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">Aucun utilisateur</td></tr>';
        return;
    }

    users.forEach(user => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>
                <div class="action-buttons">
                    <button class="btn-icon btn-edit" onclick="openEditUser('${user.id}')" title="Modifier">
                        <svg class="icon-edit" viewBox="0 0 24 24" fill="currentColor">
                            <path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/>
                        </svg>
                    </button>
                    <button class="btn-icon btn-delete" onclick="deleteUser('${user.id}')" title="Supprimer">
                        <svg class="icon-delete" viewBox="0 0 24 24" fill="currentColor">
                            <path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/>
                        </svg>
                    </button>
                </div>
            </td>
            <td>${escapeHtml(user.name || '')}</td>
            <td>${escapeHtml(user.username || '')}</td>
            <td>${escapeHtml(user.role || '')}</td>
            <td>${user.created_at ? new Date(user.created_at).toLocaleDateString() : ''}</td>
        `;
        tbody.appendChild(tr);
    });
}

function openAddUser() {
    document.getElementById('userModalTitle').textContent = 'Ajouter un utilisateur';
    document.getElementById('userId').value = '';
    document.getElementById('user-name').value = '';
    document.getElementById('user-username').value = '';
    document.getElementById('user-password').value = '';
    document.getElementById('user-password-confirm').value = '';
    document.getElementById('user-role').value = 'user';
    document.getElementById('userModal').classList.add('active');
}

async function openEditUser(id) {
    try {
        const user = await getUserById(id);

        document.getElementById('userModalTitle').textContent = 'Modifier l\'utilisateur';
        document.getElementById('userId').value = user.id;
        document.getElementById('user-name').value = user.name || '';
        document.getElementById('user-username').value = user.username || '';
        document.getElementById('user-password').value = '';
        document.getElementById('user-password-confirm').value = '';
        document.getElementById('user-role').value = user.role || 'user';

        document.getElementById('userModal').classList.add('active');
    } catch (e) {
        toast('Erreur: ' + e.message, 'err');
    }
}

async function handleUserFormSubmit(e) {
    e.preventDefault();

    const id = document.getElementById('userId').value;
    const name = document.getElementById('user-name').value.trim();
    const username = document.getElementById('user-username').value.trim();
    const password = document.getElementById('user-password').value;
    const passwordConfirm = document.getElementById('user-password-confirm').value;
    const role = document.getElementById('user-role').value;

    if (password !== passwordConfirm) {
        toast('Les mots de passe ne correspondent pas', 'err');
        return;
    }

    const userData = { name, username, role };
    if (password) {
        userData.password = password;
    }

    await saveUser(userData, id);
}

function refreshUsers() {
    loadUsers();
}

function sortUsersTable(column) {
    // Tri similaire à sortTable pour les articles
}
