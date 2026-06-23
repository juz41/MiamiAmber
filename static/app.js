const base_url = 'https://amber.miami.monster/api';
let jwtToken = localStorage.getItem("jwt")||null;
let currentFilter = {type: 'all'};

function getCurrentUser() {
    if (!jwtToken) return null;
    try {
        const payload = jwtToken.split('.')[1].replace(/-/g,'+').replace(/_/g,'/');
        return JSON.parse(atob(payload)); // {id, name, exp}
    } catch { return null; }
}

function authHeaders(json = true) {
    const h = {};
    if (json) h['Content-Type'] = 'application/json';
    if (jwtToken) h['Authorization'] = `Bearer ${jwtToken}`;
    return h;
}

const tabs = document.querySelectorAll('.tab');
const contents = document.querySelectorAll('.tab-content');
tabs.forEach(tab=>{
    tab.addEventListener('click', ()=>{
        tabs.forEach(t=>t.classList.remove('active'));
        contents.forEach(c=>c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById(tab.dataset.tab).classList.add('active');
    });
});
document.getElementById("logoutBtn").addEventListener("click", () => {
    localStorage.removeItem("jwt");
    jwtToken = null;
    updateLoginUI();
    alert("Logged out");
    tabs[0].click();
});


document.getElementById("loadFromMBID").addEventListener("click", async () => {
    const form = document.getElementById("createForm");
    const mbid = form.mbid.value.trim();

    if (!mbid) {
        alert("Please enter a MusicBrainz ID");
        return;
    }

    try {
        const res = await fetch(
            `https://musicbrainz.org/ws/2/release/${mbid}?inc=artists+tags&fmt=json`
        );

        if (!res.ok) {
            alert("Invalid MBID or not found");
            return;
        }

        const data = await res.json();

        if (data.title) {
            form.album.value = data.title;
        }

        if (data["artist-credit"]?.length) {
            form.artist.value = data["artist-credit"]
                .map(a => a.name)
                .join(", ");
        }

        if (Array.isArray(data.tags)) {
            form.tags.value = data.tags
                .slice(0, 5)
                .map(t => t.name)
                .join(", ");
        }

        alert("Album data loaded from MusicBrainz");

    } catch (err) {
        console.error(err);
        alert("Error loading data from MusicBrainz");
    }
});


function getImageQuality() {
    return localStorage.getItem('imageQuality') || '500';
}

function loadCoverArt(mbid, imgElement) {
    if (!mbid) return;
    const quality = getImageQuality();
    if (quality === 'off') { imgElement.style.display = 'none'; return; }
    imgElement.src = `https://coverartarchive.org/release/${mbid}/front-${quality}`;
    imgElement.alt = "Album cover";
    imgElement.style.display = 'block';
}




function renderPostTile(post, options = {}) {
    const {
        showUser = true,
        userNameOverride = null
    } = options;

    const title = post.title || 'Untitled';
    const artist = post.artist || 'Unknown artist';
    const album = post.album || 'Unknown album';
    const text = post.text || '';
    const rating = post.rating != null ? post.rating : 'N/A';
    const date = post.date ? new Date(post.date).toLocaleDateString() : 'Unknown date';
    const userName = userNameOverride || post.user?.name || 'Unknown';
    const mbid = post.musicbrainz_id;
    const tags = post.tags || [];
    const me = getCurrentUser();
    const isOwner = me && post.user && post.user.id === me.id;

    const div = document.createElement('div');
    div.className = 'post-tile';

    // Cover image
    const img = document.createElement('img');
    img.style.width = '100%';
    img.style.marginBottom = '8px';
    img.style.display = 'none';

    if (mbid) {
        loadCoverArt(mbid, img);
        img.style.display = 'block';
    }

    div.appendChild(img);

    div.insertAdjacentHTML('beforeend', `
        <h3>${title}</h3>
        <p><strong>${artist}</strong> — ${album}</p>
        ${mbid ? `<p>MBID: ${mbid}</p>` : ''}
	<p>${text.replace(/\n/g, '<br>')}</p>
        <p>Rating: ${rating}</p>
        ${tags.length ? `<p>${tags.map(t => `<span class="tag-pill" data-tag="${t}">#${t}</span>`).join('')}</p>` : ''}
        ${showUser ? `<p><em>by ${userName} · ${date}</em></p>` : ''}
        ${isOwner ? `
        <div class="owner-actions">
            <button type="button" class="button edit-btn" data-id="${post.id}">Edit</button>
            <button type="button" class="button delete-btn" data-id="${post.id}">Delete</button>
        </div>` : ''}
    `);

    return div;
}

async function loadPosts(filter = {type: 'all'}) {
    currentFilter = filter;
    const container = document.getElementById('recentPosts');
    const labelEl = document.getElementById('postsLabel');
    container.innerHTML = 'Loading...';

    let url, label, needsAuth = false;
    switch (filter.type) {
        case 'following':
            url = `${base_url}/posts/following`;
            label = 'Posts from people you follow';
            needsAuth = true;
            break;
        case 'tag':
            url = `${base_url}/tags/${encodeURIComponent(filter.tag)}`;
            label = `Tagged "${filter.tag}"`;
            break;
        case 'search':
            url = `${base_url}/search?q=${encodeURIComponent(filter.q)}`;
            label = `Search results for "${filter.q}"`;
            break;
        default:
            url = `${base_url}/posts`;
            label = 'Recent Posts';
    }
    labelEl.textContent = label;

    try {
        const res = await fetch(url, needsAuth ? { headers: authHeaders(false) } : {});
        if (!res.ok) throw new Error("Failed");
        const posts = await res.json();
        container.innerHTML = '';
        if (posts.length === 0) {
            container.innerHTML = 'No posts found.';
            return;
        }
        posts.forEach(post => container.appendChild(renderPostTile(post)));
    } catch (e) { console.error(e); container.innerHTML = 'Error loading posts'; }
}

document.querySelectorAll('.view-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        loadPosts({type: btn.dataset.view});
    });
});

document.getElementById('searchForm').addEventListener('submit', e => {
    e.preventDefault();
    const q = e.target.q.value.trim();
    if (!q) return;
    document.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
    loadPosts({type: 'search', q});
});

async function enterEditMode(id) {
    try {
        const res = await fetch(`${base_url}/posts/${id}`, { headers: authHeaders(false) });
        if (!res.ok) { alert('Could not load post'); return; }
        const post = await res.json();
        const form = document.getElementById('createForm');
        form.title.value = post.title || '';
        form.artist.value = post.artist || '';
        form.album.value = post.album || '';
        form.mbid.value = post.musicbrainz_id || '';
        form.text.value = post.text || '';
        form.tags.value = (post.tags || []).join(', ');
        form.rating.value = post.rating ?? 0;
        form.dataset.editId = id;
        document.getElementById('createSubmitBtn').textContent = 'Update Post';
        document.getElementById('cancelEditBtn').style.display = 'inline-block';
        document.querySelector('.tab[data-tab="create"]').click();
    } catch (e) { console.error(e); alert('Error loading post'); }
}

function exitEditMode() {
    const form = document.getElementById('createForm');
    delete form.dataset.editId;
    form.reset();
    document.getElementById('createSubmitBtn').textContent = 'Submit';
    document.getElementById('cancelEditBtn').style.display = 'none';
}
document.getElementById('cancelEditBtn').addEventListener('click', exitEditMode);

async function deletePost(id) {
    if (!confirm('Delete this post?')) return;
    try {
        const res = await fetch(`${base_url}/posts/${id}`, { method: 'DELETE', headers: authHeaders(false) });
        if (res.ok) loadPosts(currentFilter);
        else alert('Delete failed');
    } catch (e) { console.error(e); alert('Error deleting post'); }
}

// Delegated handling for tag pills and per-post owner actions,
// since tiles are re-rendered on every load.
document.body.addEventListener('click', e => {
    const tagEl = e.target.closest('.tag-pill');
    if (tagEl) {
        document.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
        loadPosts({type: 'tag', tag: tagEl.dataset.tag});
        tabs[0].click();
        return;
    }
    const editBtn = e.target.closest('.edit-btn');
    if (editBtn) { enterEditMode(editBtn.dataset.id); return; }

    const delBtn = e.target.closest('.delete-btn');
    if (delBtn) { deletePost(delBtn.dataset.id); return; }
});

document.getElementById("userSearchForm").addEventListener("submit", e => {
    e.preventDefault();
    loadUserProfile(e.target.nickname.value.trim());
});

async function loadUserProfile(nickname) {
    const infoContainer = document.getElementById("userInfo");
    const actionsContainer = document.getElementById("followActions");
    const postsContainer = document.getElementById("userPosts");

    infoContainer.innerHTML = '';
    actionsContainer.innerHTML = '';
    postsContainer.innerHTML = '';

    if (!nickname) {
        infoContainer.innerHTML = 'Please enter a username.';
        return;
    }

    try {
        const res = await fetch(`${base_url}/users/byname/${encodeURIComponent(nickname)}`);
        if (!res.ok) {
            infoContainer.innerHTML = res.status === 404 ? 'User not found' : 'Error loading user';
            return;
        }

        const data = await res.json();
        const user = data.user;
        const posts = Array.isArray(data.posts) ? data.posts : [];

        const [followers, following] = await Promise.all([
            fetch(`${base_url}/users/${user.id}/followers`).then(r => r.ok ? r.json() : []),
            fetch(`${base_url}/users/${user.id}/following`).then(r => r.ok ? r.json() : [])
        ]);

        infoContainer.innerHTML = `
            <p><strong>Nickname:</strong> ${user.name || nickname}</p>
            <p><strong>Description:</strong> ${user.description || 'No description'}</p>
            <p><strong>Total posts:</strong> ${posts.length}</p>
            <p><strong>Followers (${followers.length}):</strong> ${followers.map(f => f.name).join(', ') || '—'}</p>
            <p><strong>Following (${following.length}):</strong> ${following.map(f => f.name).join(', ') || '—'}</p>
        `;

        const me = getCurrentUser();
        if (me && me.id !== user.id) {
            const amFollowing = followers.some(f => f.id === me.id);
            const btn = document.createElement('button');
            btn.className = 'button';
            btn.textContent = amFollowing ? 'Unfollow' : 'Follow';
            btn.addEventListener('click', async () => {
                btn.disabled = true;
                try {
                    const res2 = await fetch(`${base_url}/users/${user.id}/follow`, {
                        method: amFollowing ? 'DELETE' : 'POST',
                        headers: authHeaders(false)
                    });
                    if (res2.ok) loadUserProfile(nickname);
                    else alert('Action failed');
                } catch (err) { console.error(err); alert('Error'); btn.disabled = false; }
            });
            actionsContainer.appendChild(btn);
        }

        if (posts.length === 0) {
            postsContainer.innerHTML = 'No posts yet.';
        } else {
            posts.forEach(p => postsContainer.appendChild(
                renderPostTile(p, { showUser: true, userNameOverride: user.name })
            ));
        }
    } catch (err) {
        console.error(err);
        infoContainer.innerHTML = 'Error loading user';
    }
}

document.getElementById("createForm").addEventListener("submit", async e=>{
    e.preventDefault();
    const form=e.target;
    const editId = form.dataset.editId;
    const data={
        title: form.title.value,
        artist: form.artist.value,
        album: form.album.value,
        musicBrainzId: form.mbid.value.trim() || null,
        text: form.text.value,
        tags: form.tags.value.split(',').map(t=>t.trim()).filter(Boolean),
	rating: Number(form.rating.value)
    };
    try{
        const res = await fetch(`${base_url}/posts${editId ? '/' + editId : ''}`, {
            method: editId ? "PUT" : "POST",
            headers: authHeaders(),
            body: JSON.stringify(data)
        });
        if(res.ok){
            alert(editId ? "Post updated" : "Post created");
            exitEditMode();
            loadPosts({type:'all'});
            document.querySelectorAll('.view-btn').forEach(b=>b.classList.remove('active'));
            document.querySelector('.view-btn[data-view="all"]').classList.add('active');
            tabs[0].click();
        }
        else { const err = await res.text(); alert("Failed: "+err); }
    }catch(e){ console.error(e); alert("Error"); }
});

document.getElementById("loginForm").addEventListener("submit", async e=>{
    e.preventDefault();
    const username = e.target.username.value;
    const password = e.target.password.value;
    try{
        const res = await fetch(`${base_url}/login`, {
            method:"POST",
            headers: authHeaders(),
            body: JSON.stringify({username,password})
        });
        if(res.ok){
            const data = await res.json();
            jwtToken = data.token;
            localStorage.setItem("jwt", jwtToken);
            updateLoginUI();
            alert("Logged in");
            tabs[0].click();
        } else alert("Login failed");
    }catch(e){ console.error(e); alert("Login error"); }
});

document.getElementById("registerForm").addEventListener("submit", async e=>{
    e.preventDefault();
    const username = e.target.username.value;
    const password = e.target.password.value;
    try{
        const res = await fetch(`${base_url}/register`, {
            method:"POST",
            headers: authHeaders(),
            body: JSON.stringify({username,password})
        });
        if(res.ok){ alert("Registered"); e.target.reset(); }
        else { const err=await res.text(); alert("Registration failed: "+err); }
    }catch(e){ console.error(e); alert("Registration error"); }
});

function updateLoginUI() {
    const logoutSection = document.getElementById("logoutSection");
    const loginForm = document.getElementById("loginForm");
    const registerForm = document.getElementById("registerForm");
    const followingBtn = document.getElementById("followingBtn");

    if (jwtToken) {
        logoutSection.style.display = "block";
        loginForm.style.display = "none";
        registerForm.style.display = "none";
        followingBtn.style.display = "inline-block";
    } else {
        logoutSection.style.display = "none";
        loginForm.style.display = "block";
        registerForm.style.display = "block";
        followingBtn.style.display = "none";
        if (currentFilter.type === 'following') {
            document.querySelector('.view-btn[data-view="all"]').click();
        }
    }
}

loadPosts({type: 'all'});
updateLoginUI();

const imageQualityEl = document.getElementById('imageQualitySetting');
imageQualityEl.value = getImageQuality();
imageQualityEl.addEventListener('change', () => {
    localStorage.setItem('imageQuality', imageQualityEl.value);
    loadPosts(currentFilter);
});

