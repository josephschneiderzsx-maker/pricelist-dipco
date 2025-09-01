let allArticles = [];
let fullArticleListForFiltering = []; // Holds all articles for client-side filtering
let currentPage = 1;
let isLoading = false;
let hasMore = true;
let currentSearchTerm = '';
const limit = 100;
let initialLoad = true;

// Debounce function to limit API calls on search input
function debounce(func, delay) {
    let timeout;
    return function(...args) {
        const context = this;
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(context, args), delay);
    };
}

async function loadArticles(isSearch = false) {
    if (isLoading || (!hasMore && !isSearch)) return;

    isLoading = true;

    if (isSearch) {
        currentPage = 1;
        hasMore = true;
        allArticles = [];
        document.getElementById('articles-table').innerHTML = '';
        document.getElementById('articles-cards').innerHTML = '';
    }

    if (currentPage === 1) {
        showState('loading-initial');
    } else {
        showState('loading-more');
    }

    const searchTerm = document.getElementById('searchInput').value.trim();
    let url = `/api/public/articles?page=${currentPage}&limit=${limit}`;
    if (searchTerm) {
        url += `&search=${encodeURIComponent(searchTerm)}`;
    }

    try {
        const response = await fetch(url);
        if (!response.ok) throw new Error('Impossible de charger les données');

        const newArticles = await response.json();

        if (newArticles.length < limit) {
            hasMore = false;
        }

        allArticles = allArticles.concat(newArticles);
        fullArticleListForFiltering = fullArticleListForFiltering.concat(newArticles);

        if (initialLoad) {
            populateFilters(allArticles);
            initialLoad = false;
        }

        filterAndSortArticles(); // This will now filter/sort the currently loaded articles
        currentPage++;

    } catch (error) {
        showState('error', error.message);
    } finally {
        isLoading = false;
        if (allArticles.length > 0) {
            showState('table');
        } else if (!hasMore) {
            showState('empty');
        }
    }
}

function populateFilters(articles) {
    const types = [...new Set(articles.map(article => article.type).filter(Boolean))].sort();
    const typeFilter = document.getElementById('typeFilter');
    typeFilter.innerHTML = '<option value="">Tous les types</option>';
    types.forEach(type => {
        const option = document.createElement('option');
        option.value = type;
        option.textContent = type;
        typeFilter.appendChild(option);
    });

    const demars = [...new Set(articles.map(article => article.demar).filter(Boolean))].sort();
    const demarFilter = document.getElementById('demarFilter');
    demarFilter.innerHTML = '<option value="">Tous les Demar.</option>';
    demars.forEach(demar => {
        const option = document.createElement('option');
        option.value = demar;
        option.textContent = demar;
        demarFilter.appendChild(option);
    });
}

function filterAndSortArticles() {
    const selectedType = document.getElementById('typeFilter').value;
    const selectedDemar = document.getElementById('demarFilter').value;
    const sortOption = document.getElementById('sortOptions').value;
    const sortOptionMobile = document.getElementById('sortOptionsMobile').value;
    const currentSort = sortOption || sortOptionMobile;

    let filteredArticles = allArticles.filter(article => {
        const matchesType = !selectedType || article.type === selectedType;
        const matchesDemar = !selectedDemar || article.demar === selectedDemar;
        return matchesType && matchesDemar;
    });

    switch (currentSort) {
        case 'code-asc':
            filteredArticles.sort((a, b) => (a.code || '').localeCompare(b.code || ''));
            break;
        case 'code-desc':
            filteredArticles.sort((a, b) => (b.code || '').localeCompare(a.code || ''));
            break;
        case 'price-asc':
            filteredArticles.sort((a, b) => (a.prix_vente || 0) - (b.prix_vente || 0));
            break;
        case 'price-desc':
            filteredArticles.sort((a, b) => (b.prix_vente || 0) - (a.prix_vente || 0));
            break;
        case 'desc-asc':
            filteredArticles.sort((a, b) => (a.description || '').localeCompare(b.description || ''));
            break;
        case 'desc-desc':
            filteredArticles.sort((a, b) => (b.description || '').localeCompare(a.description || ''));
            break;
        default:
            break;
    }

    renderArticles(filteredArticles);
    renderCards(filteredArticles);
    updateStats(filteredArticles.length);
     if (filteredArticles.length === 0 && !hasMore && !isLoading) {
        showState('empty');
    }
}

function renderArticles(articles) {
    const tableBody = document.getElementById('articles-table');
    tableBody.innerHTML = '';

    if (articles.length === 0 && !hasMore && !isLoading) {
        showState('empty');
        return;
    }

    showState('table');

    articles.forEach(article => {
        const row = document.createElement('tr');
        row.className = 'hover:bg-gray-50';
        row.innerHTML = `
            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${article.code || '—'}</td>
            <td class="px-6 py-4 whitespace-normal text-sm text-gray-600">${article.description || '—'}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600">${article.demar || '—'}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm font-semibold text-dipco-700">${formatCurrency(article.prix_vente)}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600">${formatDecimal(article.achat_minimum)}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600">${article.unite || '—'}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm">
                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-primary-100 text-primary-800">${article.type || '—'}</span>
            </td>
        `;
        tableBody.appendChild(row);
    });
}

function renderCards(articles) {
    const cardsContainer = document.getElementById('articles-cards');
    cardsContainer.innerHTML = '';

    articles.forEach(article => {
        const card = document.createElement('div');
        card.className = 'article-card p-4';
        card.innerHTML = `
            <div class="flex justify-between items-start mb-3">
                <div class="flex-1">
                    <h3 class="text-lg font-semibold text-gray-900 mb-1">${article.code || '—'}</h3>
                    <p class="text-sm text-gray-600 line-clamp-2">${article.description || '—'}</p>
                </div>
                <div class="ml-3">
                    <span class="px-2 py-1 text-xs font-semibold rounded-full bg-primary-100 text-primary-800">${article.type || '—'}</span>
                </div>
            </div>
            <div class="grid grid-cols-2 gap-4 text-sm">
                <div>
                    <span class="text-gray-500">Demar.:</span>
                    <span class="font-medium text-gray-900 ml-1">${article.demar || '—'}</span>
                </div>
                <div>
                    <span class="text-gray-500">Unité:</span>
                    <span class="font-medium text-gray-900 ml-1">${article.unite || '—'}</span>
                </div>
                <div>
                    <span class="text-gray-500">Prix:</span>
                    <span class="font-bold text-dipco-700 ml-1">${formatCurrency(article.prix_vente)}</span>
                </div>
                <div>
                    <span class="text-gray-500">Achat Min.:</span>
                    <span class="font-medium text-gray-900 ml-1">${formatDecimal(article.achat_minimum)}</span>
                </div>
            </div>
        `;
        cardsContainer.appendChild(card);
    });
}

function showState(state, message = '') {
    const loadingEl = document.getElementById('loading');
    const infiniteLoaderEl = document.getElementById('infinite-loader');
    const errorEl = document.getElementById('error-message');
    const emptyEl = document.getElementById('empty-state');
    const desktopTable = document.querySelector('.desktop-table');
    const mobileCards = document.querySelector('.mobile-cards');

    loadingEl.classList.add('hidden');
    infiniteLoaderEl.classList.add('hidden');
    errorEl.classList.add('hidden');
    emptyEl.classList.add('hidden');

    switch(state) {
        case 'loading-initial':
            loadingEl.classList.remove('hidden');
            desktopTable.classList.add('hidden');
            mobileCards.classList.add('hidden');
            break;
        case 'loading-more':
            infiniteLoaderEl.classList.remove('hidden');
            break;
        case 'error':
            errorEl.classList.remove('hidden');
            document.getElementById('error-text').textContent = message;
            desktopTable.classList.add('hidden');
            mobileCards.classList.add('hidden');
            break;
        case 'empty':
            emptyEl.classList.remove('hidden');
            desktopTable.classList.add('hidden');
            mobileCards.classList.add('hidden');
            break;
        case 'table':
        case 'cards':
            desktopTable.classList.remove('hidden');
            mobileCards.classList.remove('hidden');
            break;
    }
}

function formatCurrency(value) {
    if (value === null || value === undefined) return '—';
    return new Intl.NumberFormat('fr-FR', {
        style: 'currency',
        currency: 'USD',
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    }).format(value);
}

function formatDecimal(value) {
    if (value === null || value === undefined) return '—';
    return new Intl.NumberFormat('fr-FR', {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    }).format(value);
}

function updateStats(count) {
    document.getElementById('article-count').textContent = `${count} article${count > 1 ? 's' : ''}`;
    document.getElementById('article-count-mobile').textContent = `${count} article${count > 1 ? 's' : ''}`;
}

function syncSortOptions() {
    const desktopSort = document.getElementById('sortOptions');
    const mobileSort = document.getElementById('sortOptionsMobile');

    const handleSortChange = () => {
        mobileSort.value = desktopSort.value;
        filterAndSortArticles();
    };

    desktopSort.addEventListener('change', () => {
        mobileSort.value = desktopSort.value;
        filterAndSortArticles();
    });

    mobileSort.addEventListener('change', () => {
        desktopSort.value = mobileSort.value;
        filterAndSortArticles();
    });
}

const debouncedSearch = debounce(() => loadArticles(true), 300);
document.getElementById('searchInput').addEventListener('input', debouncedSearch);

document.getElementById('typeFilter').addEventListener('change', filterAndSortArticles);
document.getElementById('demarFilter').addEventListener('change', filterAndSortArticles);

window.addEventListener('scroll', () => {
    if ((window.innerHeight + window.scrollY) >= document.body.offsetHeight - 500 && hasMore && !isLoading) {
        loadArticles();
    }
});

window.addEventListener('DOMContentLoaded', () => {
    loadArticles();
    syncSortOptions();
});
