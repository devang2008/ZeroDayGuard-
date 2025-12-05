// TechMart E-Commerce Application

const API_BASE = 'http://localhost:3000/api';
let currentUser = null;
let cart = [];
let currentProductId = null;
let allProducts = [];

// Initialize app
document.addEventListener('DOMContentLoaded', function() {
    loadProducts();
    updateCartCount();
    checkSavedUser();
});

// Page navigation with smooth transitions
function showPage(pageName) {
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    
    const page = document.getElementById(pageName + 'Page');
    if (page) {
        page.classList.add('active');
    }
    
    // Require login for certain pages
    if (['products', 'cart', 'profile'].includes(pageName)) {
        if (!currentUser) {
            showPage('login');
            showAlert('Please login to continue', 'info');
            return;
        }
    }
    
    // Load data when switching pages
    if (pageName === 'products') {
        loadProducts();
    } else if (pageName === 'cart') {
        displayCart();
    } else if (pageName === 'profile') {
        loadProfile();
    }
}

// User Authentication
async function login(event) {
    event.preventDefault();
    
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;
    
    const loginBtn = event.target.querySelector('button[type="submit"]');
    loginBtn.disabled = true;
    loginBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Logging in...';
    
    try {
        const response = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, password})
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentUser = data.user;
            localStorage.setItem('user', JSON.stringify(currentUser));
            
            updateUserNav();
            showPage('home');
            showAlert(`Welcome back, ${currentUser.username}!`, 'success');
        } else {
            showAlert(data.error || 'Invalid credentials', 'error');
        }
    } catch (error) {
        showAlert('An error occurred. Please try again.', 'error');
    } finally {
        loginBtn.disabled = false;
        loginBtn.innerHTML = '<i class="fas fa-sign-in-alt"></i> Login';
    }
}

async function register(event) {
    event.preventDefault();
    
    const username = document.getElementById('regUsername').value;
    const email = document.getElementById('regEmail').value;
    const password = document.getElementById('regPassword').value;
    
    const registerBtn = event.target.querySelector('button[type="submit"]');
    registerBtn.disabled = true;
    registerBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creating account...';
    
    try {
        const response = await fetch(`${API_BASE}/register`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username, email, password})
        });
        
        const data = await response.json();
        
        if (data.success) {
            showAlert('Account created successfully! Please login.', 'success');
            showPage('login');
            document.getElementById('loginUsername').value = username;
        } else {
            showAlert(data.error || 'Registration failed', 'error');
        }
    } catch (error) {
        showAlert('An error occurred. Please try again.', 'error');
    } finally {
        registerBtn.disabled = false;
        registerBtn.innerHTML = '<i class="fas fa-user-plus"></i> Create Account';
    }
}

function updateUserNav() {
    const userNav = document.getElementById('userNav');
    
    if (currentUser) {
        userNav.innerHTML = `
            <span style="color: white; font-weight: 600;">
                <i class="fas fa-user"></i> ${currentUser.username}
            </span>
            <a href="#" onclick="showPage('profile')"><i class="fas fa-user-circle"></i> Profile</a>
            <a href="#" onclick="logout()"><i class="fas fa-sign-out-alt"></i> Logout</a>
        `;
    } else {
        userNav.innerHTML = `
            <a href="#" onclick="showPage('login')"><i class="fas fa-sign-in-alt"></i> Login</a>
            <a href="#" onclick="showPage('register')"><i class="fas fa-user-plus"></i> Register</a>
        `;
    }
}

function logout() {
    currentUser = null;
    localStorage.removeItem('user');
    updateUserNav();
    showPage('home');
    showAlert('You have been logged out', 'success');
}

function checkSavedUser() {
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
        currentUser = JSON.parse(savedUser);
        updateUserNav();
    }
}

// Product Management
async function searchProducts() {
    const searchTerm = document.getElementById('searchInput').value;
    
    if (!searchTerm) {
        loadProducts();
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/products/search?q=${searchTerm}`);
        const products = await response.json();
        
        if (products.error) {
            showAlert('Search error occurred', 'error');
            displayProducts(allProducts);
        } else {
            displayProducts(products);
        }
    } catch (error) {
        console.error('Search error:', error);
        displayProducts(allProducts);
    }
}

async function loadProducts() {
    try {
        const response = await fetch(`${API_BASE}/products`);
        const products = await response.json();
        
        allProducts = products;
        displayProducts(products);
    } catch (error) {
        console.error('Error loading products:', error);
        showAlert('Failed to load products', 'error');
    }
}

function sortProducts() {
    const sortBy = document.getElementById('sortBy').value;
    let sorted = [...allProducts];
    
    switch(sortBy) {
        case 'price-low':
            sorted.sort((a, b) => a.price - b.price);
            break;
        case 'price-high':
            sorted.sort((a, b) => b.price - a.price);
            break;
        case 'name':
            sorted.sort((a, b) => a.name.localeCompare(b.name));
            break;
        case 'popularity':
            sorted.reverse();
            break;
    }
    
    displayProducts(sorted);
}

function displayProducts(products) {
    const productsList = document.getElementById('productsList');
    
    if (!productsList) return;
    
    if (products.length === 0) {
        productsList.innerHTML = '<div class="cart-empty"><i class="fas fa-search"></i><h3>No products found</h3></div>';
        return;
    }
    
    productsList.innerHTML = products.map(product => `
        <div class="product-card" onclick="showProduct(${product.id})">
            <div class="product-image" style="background-image: url('${product.image}');">
            </div>
            <div class="product-info">
                <div class="product-name">${product.name}</div>
                <div class="product-description">${product.description}</div>
                <div class="product-price">₹${product.price.toFixed(2)}</div>
                <div class="product-stock">
                    <i class="fas fa-check-circle"></i> ${product.stock} in stock
                </div>
                <button onclick="addToCart(${product.id}, event)" class="btn btn-primary btn-block">
                    <i class="fas fa-cart-plus"></i> Add to Cart
                </button>
            </div>
        </div>
    `).join('');
}

function getProductIcon(name) {
    // Return actual product image URL instead of emoji
    return '';
}

async function showProduct(productId) {
    currentProductId = productId;
    
    try {
        const product = allProducts.find(p => p.id === productId);
        
        if (product) {
            const detailPage = document.getElementById('productDetail');
            detailPage.innerHTML = `
                <div class="product-detail">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; align-items: start;">
                        <div>
                            <div class="product-image" style="height: 400px; background-image: url('${product.image}'); border-radius: 12px;">
                            </div>
                        </div>
                        <div>
                            <h2 style="font-size: 2rem; margin-bottom: 1rem;">${product.name}</h2>
                            <div class="rating-stars" style="margin-bottom: 1rem;">
                                <i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i>
                                <i class="fas fa-star"></i><i class="fas fa-star-half-alt"></i>
                                <span style="color: var(--gray); margin-left: 0.5rem;">4.5 (127 reviews)</span>
                            </div>
                            <div class="product-price" style="margin: 1.5rem 0;">₹${product.price.toFixed(2)}</div>
                            <p style="color: var(--gray); line-height: 1.8; margin-bottom: 2rem;">${product.description}</p>
                            <div style="margin-bottom: 2rem;">
                                <strong style="color: var(--success);">
                                    <i class="fas fa-check-circle"></i> ${product.stock} units available
                                </strong>
                            </div>
                            <button onclick="addToCart(${product.id}, event)" class="btn btn-primary btn-large">
                                <i class="fas fa-cart-plus"></i> Add to Cart
                            </button>
                        </div>
                    </div>
                </div>
            `;
            
            loadComments(productId);
            showPage('productDetail');
        }
    } catch (error) {
        console.error('Error loading product:', error);
        showAlert('Failed to load product details', 'error');
    }
}

// Comments/Reviews
async function loadComments(productId) {
    try {
        const response = await fetch(`${API_BASE}/comments/${productId}`);
        const comments = await response.json();
        
        const commentsList = document.getElementById('commentsList');
        
        if (comments.length === 0) {
            commentsList.innerHTML = '<p class="text-muted">No reviews yet. Be the first to review this product!</p>';
        } else {
            commentsList.innerHTML = comments.map(comment => `
                <div class="comment">
                    <div class="comment-author">
                        <i class="fas fa-user-circle"></i> ${comment.username}
                    </div>
                    <div class="rating-stars" style="font-size: 0.875rem; color: var(--accent); margin: 0.5rem 0;">
                        <i class="fas fa-star"></i><i class="fas fa-star"></i><i class="fas fa-star"></i>
                        <i class="fas fa-star"></i><i class="fas fa-star"></i>
                    </div>
                    <div class="comment-text">${comment.comment}</div>
                </div>
            `).join('');
        }
    } catch (error) {
        console.error('Error loading comments:', error);
    }
}

async function addComment() {
    if (!currentUser) {
        showAlert('Please login to leave a review', 'info');
        showPage('login');
        return;
    }
    
    const comment = document.getElementById('commentText').value.trim();
    
    if (!comment) {
        showAlert('Please write a review', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/comments`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                product_id: currentProductId,
                comment: comment
            })
        });
        
        if (response.ok) {
            document.getElementById('commentText').value = '';
            loadComments(currentProductId);
            showAlert('Review submitted successfully!', 'success');
        }
    } catch (error) {
        console.error('Error adding comment:', error);
        showAlert('Failed to submit review', 'error');
    }
}

// Shopping Cart Management
function addToCart(productId, event) {
    if (event) event.stopPropagation();
    
    const product = allProducts.find(p => p.id === productId);
    if (!product) return;
    
    // Check if product already in cart
    const existingItem = cart.find(item => item.id === productId);
    
    if (existingItem) {
        existingItem.quantity += 1;
    } else {
        cart.push({
            id: productId,
            name: product.name,
            price: product.price,
            quantity: 1,
            image: product.image
        });
    }
    
    updateCartCount();
    showAlert(`${product.name} added to cart!`, 'success');
}

function updateCartCount() {
    const totalItems = cart.reduce((sum, item) => sum + item.quantity, 0);
    document.getElementById('cartCount').textContent = totalItems;
}

function displayCart() {
    const cartItems = document.getElementById('cartItems');
    const cartSubtotal = document.getElementById('cartSubtotal');
    const cartTax = document.getElementById('cartTax');
    const cartTotal = document.getElementById('cartTotal');
    const cartShipping = document.getElementById('cartShipping');
    
    if (cart.length === 0) {
        cartItems.innerHTML = `
            <div class="cart-empty">
                <i class="fas fa-shopping-cart"></i>
                <h3>Your cart is empty</h3>
                <p>Start shopping to add items to your cart</p>
                <button onclick="showPage('products')" class="btn btn-primary" style="margin-top: 1rem;">
                    <i class="fas fa-shopping-bag"></i> Browse Products
                </button>
            </div>
        `;
        
        if (cartSubtotal) cartSubtotal.textContent = '$0.00';
        if (cartTax) cartTax.textContent = '$0.00';
        if (cartTotal) cartTotal.textContent = '$0.00';
        return;
    }
    
    let subtotal = 0;
    
    const items = cart.map(item => {
        const itemTotal = item.price * item.quantity;
        subtotal += itemTotal;
        
        return `
            <div class="cart-item">
                <div class="cart-item-image" style="background-image: url('${item.image}');"></div>
                <div class="cart-item-info">
                    <div class="cart-item-name">${item.name}</div>
                    <div class="cart-item-price">₹${item.price.toFixed(2)}</div>
                    <div class="cart-item-quantity">
                        <button onclick="updateQuantity(${item.id}, -1)">
                            <i class="fas fa-minus"></i>
                        </button>
                        <span>${item.quantity}</span>
                        <button onclick="updateQuantity(${item.id}, 1)">
                            <i class="fas fa-plus"></i>
                        </button>
                    </div>
                </div>
                <div>
                    <div style="font-size: 1.25rem; font-weight: 700; color: var(--primary); margin-bottom: 1rem;">
                        ₹${itemTotal.toFixed(2)}
                    </div>
                    <button onclick="removeFromCart(${item.id})" class="cart-item-remove">
                        <i class="fas fa-trash"></i> Remove
                    </button>
                </div>
            </div>
        `;
    }).join('');
    
    const shipping = subtotal > 50 ? 0 : 9.99;
    const tax = subtotal * 0.08;
    const total = subtotal + shipping + tax;
    
    cartItems.innerHTML = items;
    if (cartSubtotal) cartSubtotal.textContent = `₹${subtotal.toFixed(2)}`;
    if (cartShipping) cartShipping.textContent = shipping === 0 ? 'Free' : `₹${shipping.toFixed(2)}`;
    if (cartTax) cartTax.textContent = `₹${tax.toFixed(2)}`;
    if (cartTotal) cartTotal.textContent = `₹${total.toFixed(2)}`;
}

function updateQuantity(productId, change) {
    const item = cart.find(i => i.id === productId);
    if (!item) return;
    
    item.quantity += change;
    
    if (item.quantity <= 0) {
        removeFromCart(productId);
    } else {
        updateCartCount();
        displayCart();
    }
}

function removeFromCart(productId) {
    cart = cart.filter(item => item.id !== productId);
    updateCartCount();
    displayCart();
    showAlert('Item removed from cart', 'success');
}

function checkout() {
    if (cart.length === 0) {
        showAlert('Your cart is empty', 'error');
        return;
    }
    
    if (!currentUser) {
        showAlert('Please login to checkout', 'info');
        showPage('login');
        return;
    }
    
    const total = cart.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    
    showAlert(`Order placed successfully! Total: ₹${total.toFixed(2)}`, 'success');
    cart = [];
    updateCartCount();
    showPage('home');
}

// Profile Management
function loadProfile() {
    document.getElementById('profileUsername').textContent = currentUser.username;
    document.getElementById('profileEmail').value = currentUser.email || '';
    document.getElementById('profileRole').textContent = currentUser.role || 'user';
    document.getElementById('profilePhone').value = currentUser.phone || '';
}

async function updateProfile(event) {
    event.preventDefault();
    
    const email = document.getElementById('profileEmail').value;
    const phone = document.getElementById('profilePhone').value;
    
    try {
        const response = await fetch(`${API_BASE}/profile/update`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({email, phone})
        });
        
        if (response.ok) {
            currentUser.email = email;
            currentUser.phone = phone;
            localStorage.setItem('user', JSON.stringify(currentUser));
            showAlert('Profile updated successfully!', 'success');
        } else {
            showAlert('Failed to update profile', 'error');
        }
    } catch (error) {
        console.error('Error updating profile:', error);
        showAlert('An error occurred', 'error');
    }
}

// Alert System
function showAlert(message, type) {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type}`;
    
    const icon = type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle';
    alertDiv.innerHTML = `<i class="fas fa-${icon}"></i> ${message}`;
    
    const container = document.querySelector('.container');
    const firstChild = container ? container.firstChild : document.body.firstChild;
    
    if (container) {
        container.insertBefore(alertDiv, firstChild);
    } else {
        document.body.insertBefore(alertDiv, firstChild);
    }
    
    setTimeout(() => {
        alertDiv.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => alertDiv.remove(), 300);
    }, 3000);
}

// Star rating interaction
document.addEventListener('click', function(e) {
    if (e.target.classList.contains('far') && e.target.classList.contains('fa-star')) {
        const rating = e.target.getAttribute('data-rating');
        const stars = e.target.parentElement.querySelectorAll('.fa-star');
        
        stars.forEach((star, index) => {
            if (index < rating) {
                star.classList.remove('far');
                star.classList.add('fas', 'active');
            } else {
                star.classList.remove('fas', 'active');
                star.classList.add('far');
            }
        });
    }
});

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl+K or Cmd+K for search
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        showPage('products');
        setTimeout(() => document.getElementById('searchInput')?.focus(), 100);
    }
});

// ============================================
// VULNERABILITY TESTING FUNCTIONS
// ============================================

// Command Injection Test (CWE-78)
async function processImage() {
    const imageName = document.getElementById('imageProcess').value;
    const output = document.getElementById('cmdOutput');
    output.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
    
    try {
        const response = await fetch(`${API_BASE}/process-image`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({image: imageName})
        });
        
        const data = await response.json();
        
        if (data.success) {
            output.innerHTML = `
                <div class="success-output">
                    <strong>✅ Command Executed!</strong><br>
                    <pre>${data.output || 'Command executed successfully'}</pre>
                    <p class="vuln-note">⚠️ This shows command injection vulnerability. 
                    User input is directly passed to shell commands!</p>
                </div>
            `;
        } else {
            output.innerHTML = `<div class="error-output"><strong>Error:</strong> ${data.error}</div>`;
        }
    } catch (error) {
        output.innerHTML = `<div class="error-output"><strong>Error:</strong> ${error.message}</div>`;
    }
}

// Path Traversal Test (CWE-22)
async function downloadFile() {
    const filename = document.getElementById('fileDownload').value;
    const output = document.getElementById('downloadOutput');
    output.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Attempting download...';
    
    try {
        const response = await fetch(`${API_BASE}/download?file=${encodeURIComponent(filename)}`);
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename.split('/').pop().split('\\').pop();
            a.click();
            
            output.innerHTML = `
                <div class="success-output">
                    <strong>✅ File Downloaded!</strong><br>
                    <p>File: <code>${filename}</code></p>
                    <p class="vuln-note">⚠️ Path traversal vulnerability! Can access files outside uploads directory.</p>
                </div>
            `;
        } else {
            const error = await response.json();
            output.innerHTML = `<div class="error-output"><strong>Error:</strong> ${error.error}</div>`;
        }
    } catch (error) {
        output.innerHTML = `<div class="error-output"><strong>Error:</strong> ${error.message}</div>`;
    }
}

// Directory Listing Test (CWE-548)
async function listDirectory() {
    const directory = document.getElementById('dirList').value;
    const output = document.getElementById('dirOutput');
    output.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Listing directory...';
    
    try {
        const response = await fetch(`${API_BASE}/files?dir=${encodeURIComponent(directory)}`);
        const data = await response.json();
        
        if (data.files) {
            let html = '<div class="success-output"><strong>✅ Directory Contents:</strong><ul class="file-list">';
            data.files.forEach(file => {
                const icon = file.is_dir ? '<i class="fas fa-folder"></i>' : '<i class="fas fa-file"></i>';
                html += `<li>${icon} ${file.name} <span class="file-path">(${file.path})</span></li>`;
            });
            html += '</ul><p class="vuln-note">⚠️ Directory traversal allowed! Sensitive files exposed.</p></div>';
            output.innerHTML = html;
        } else {
            output.innerHTML = `<div class="error-output"><strong>Error:</strong> ${data.error}</div>`;
        }
    } catch (error) {
        output.innerHTML = `<div class="error-output"><strong>Error:</strong> ${error.message}</div>`;
    }
}

// SSRF Test (CWE-918)
async function fetchImage() {
    const url = document.getElementById('fetchUrl').value;
    const output = document.getElementById('ssrfOutput');
    output.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Fetching...';
    
    try {
        const response = await fetch(`${API_BASE}/fetch-image?url=${encodeURIComponent(url)}`);
        
        if (response.ok) {
            output.innerHTML = `
                <div class="success-output">
                    <strong>✅ SSRF Request Successful!</strong><br>
                    <p>Fetched from: <code>${url}</code></p>
                    <p class="vuln-note">⚠️ Server-Side Request Forgery! Server can be used to access internal resources.</p>
                    <p>Try: <code>http://localhost:3000/api/debug</code> to see internal data!</p>
                </div>
            `;
        } else {
            const data = await response.json();
            output.innerHTML = `<div class="error-output"><strong>Error:</strong> ${data.error}</div>`;
        }
    } catch (error) {
        output.innerHTML = `<div class="error-output"><strong>Error:</strong> ${error.message}</div>`;
    }
}

// Debug Info (Hard-coded Credentials - CWE-798)
async function getDebugInfo() {
    const output = document.getElementById('debugOutput');
    output.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Fetching debug info...';
    
    try {
        const response = await fetch(`${API_BASE}/debug`);
        const data = await response.json();
        
        output.innerHTML = `
            <div class="error-output">
                <strong>🚨 CRITICAL: Exposed Sensitive Information!</strong><br><br>
                <pre>${JSON.stringify(data, null, 2)}</pre>
                <br>
                <p class="vuln-note">⚠️ Hard-coded credentials exposed! This reveals:
                <ul>
                    <li>Database path</li>
                    <li>Secret keys</li>
                    <li>API keys</li>
                    <li>Admin passwords</li>
                    <li>Environment variables</li>
                </ul>
                </p>
            </div>
        `;
    } catch (error) {
        output.innerHTML = `<div class="error-output"><strong>Error:</strong> ${error.message}</div>`;
    }
}

// IDOR Test (CWE-639)
async function getUserData() {
    const userId = document.getElementById('userId').value;
    const output = document.getElementById('idorOutput');
    output.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Fetching user data...';
    
    try {
        const response = await fetch(`${API_BASE}/user/${userId}`);
        const data = await response.json();
        
        if (data.id) {
            output.innerHTML = `
                <div class="success-output">
                    <strong>✅ Unauthorized Access Successful!</strong><br><br>
                    <strong>User Data:</strong>
                    <pre>${JSON.stringify(data, null, 2)}</pre>
                    <p class="vuln-note">⚠️ Insecure Direct Object Reference! Can access any user's data without authorization.</p>
                </div>
            `;
        } else {
            output.innerHTML = `<div class="error-output"><strong>Error:</strong> ${data.error}</div>`;
        }
    } catch (error) {
        output.innerHTML = `<div class="error-output"><strong>Error:</strong> ${error.message}</div>`;
    }
}

// Load comments with XSS vulnerability
async function loadComments(productId) {
    try {
        const response = await fetch(`${API_BASE}/comments/${productId}`);
        const comments = await response.json();
        
        const commentsList = document.getElementById('commentsList');
        if (comments.length === 0) {
            commentsList.innerHTML = '<p class="no-comments">No reviews yet. Be the first to review!</p>';
            return;
        }
        
        // VULNERABILITY: Rendering unsanitized HTML (XSS)
        let html = '';
        comments.forEach(comment => {
            html += `
                <div class="comment-card">
                    <div class="comment-header">
                        <strong><i class="fas fa-user"></i> ${comment.username}</strong>
                        <span class="comment-date">${new Date(comment.created_at).toLocaleDateString()}</span>
                    </div>
                    <div class="comment-body">${comment.comment}</div>
                </div>
            `;
        });
        
        commentsList.innerHTML = html;
    } catch (error) {
        console.error('Error loading comments:', error);
    }
}

// Add comment (XSS vulnerability)
async function addComment() {
    if (!currentProductId) {
        showAlert('Please select a product first', 'error');
        return;
    }
    
    const commentText = document.getElementById('commentText').value.trim();
    
    if (!commentText) {
        showAlert('Please enter a review', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/comments`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                product_id: currentProductId,
                comment: commentText  // Sent unsanitized!
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showAlert('Review posted successfully!', 'success');
            document.getElementById('commentText').value = '';
            loadComments(currentProductId);
        } else {
            showAlert('Failed to post review', 'error');
        }
    } catch (error) {
        showAlert('An error occurred', 'error');
    }
}

