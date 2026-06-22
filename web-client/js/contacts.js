/**
 * SafeTrack — Contacts Module
 */

let _searchDebounce;

async function loadContacts() {
  try {
    const contacts = await API.get('/contacts');
    AppState.contacts = contacts;

    const accepted = contacts.filter(c => c.status === 'ACCEPTED');
    const pending = contacts.filter(c => c.status === 'PENDING');

    // Update nav badge
    const badge = document.getElementById('pending-badge');
    const inboundPending = pending.filter(c => !c.isInitiator);
    if (badge) {
      badge.textContent = inboundPending.length;
      badge.classList.toggle('hidden', inboundPending.length === 0);
    }

    // Render contacts list
    const list = document.getElementById('contacts-list');
    if (!accepted.length) {
      list.innerHTML = '<div class="empty-state">No contacts yet. Search above to add someone.</div>';
    } else {
      list.innerHTML = accepted.map(c => renderContactItem(c)).join('');
    }

    // Render pending
    const pendingSection = document.getElementById('pending-section');
    const pendingList = document.getElementById('pending-list');
    if (inboundPending.length > 0) {
      pendingSection.classList.remove('hidden');
      pendingList.innerHTML = inboundPending.map(c => renderPendingItem(c)).join('');
    } else {
      pendingSection.classList.add('hidden');
    }

    // Sharing sub-label
    const sharingSub = document.getElementById('sharing-sub');
    if (sharingSub) {
      sharingSub.textContent = `Sharing with ${accepted.length} contact${accepted.length !== 1 ? 's' : ''}`;
    }

    // Update settings SOS group selector
    updateSosGroupSelector();

    // Load groups
    loadGroups();

    // ─── Realtime Subscriptions & GAP 3: Relay Discovery ──────────────────
    if (!AppState.isDemoMode && window.RealtimeManager) {
      accepted.forEach(c => {
        if (c.contact?.id) RealtimeManager.watchContact(c.contact.id);
        
        // GAP 3: Fetch and Cache Contact Relay Lists (NIP-65)
        if (c.contact?.npub) {
          fetchAndCacheContactRelays(c.contact.npub);
        }
      });
    }
  } catch (err) {
    // Silent fail
  }
}

/**
 * GAP 3: NIP-65 Relay Discovery
 * Fetches kind:10002 from the relay pool and caches it locally.
 */
async function fetchAndCacheContactRelays(npub) {
  try {
    const { nip19 } = await import('https://esm.sh/nostr-tools@1.17.0');
    const { data: pubkey } = nip19.decode(npub);
    
    // We check our primary relay pool for the contact's metadata
    const relays = [
      'wss://relay.damus.io',
      'wss://nos.lol',
      'wss://relay.nostr.band'
    ];

    for (const url of relays) {
      const ws = new WebSocket(url);
      ws.onopen = () => {
        ws.send(JSON.stringify(['REQ', `relays-${pubkey}`, { kinds: [10002], authors: [pubkey], limit: 1 }]));
      };
      ws.onmessage = (msg) => {
        try {
          const [type, sub, event] = JSON.parse(msg.data);
          if (type === 'EVENT' && event.kind === 10002) {
            const contactRelays = event.tags
              .filter(t => t[0] === 'r')
              .map(t => ({ url: t[1], type: t[2] || 'both' }));
            
            // Cache in AppState and Persistence (IDB)
            if (!AppState.contactRelays) AppState.contactRelays = {};
            AppState.contactRelays[npub] = contactRelays;
            
            if (window.NostrP2P) {
              NostrP2P.saveContactRelays(npub, contactRelays);
            }
            ws.close();
          }
        } catch(e) {}
      };
      ws.onerror = () => ws.close();
      // Auto-close after 5s if no response
      setTimeout(() => ws.readyState === WebSocket.OPEN && ws.close(), 5000);
    }
  } catch (e) {
    console.warn(`NIP-65 fetch failed for ${npub}:`, e);
  }
}

function renderContactItem(c) {
  const name = c.contact.displayName || c.contact.username;
  const avatar = IconResolver.getAvatar(c.contact.username || c.contact.id);
  return `
    <div class="contact-item" id="contact-item-${c.linkId}">
      <div class="contact-avatar">
        <img src="${avatar}" alt="" style="width:100%;height:100%;border-radius:50%">
      </div>
      <div class="contact-info">
        <div class="contact-name">${escHtml(name)}</div>
        <div class="contact-username">@${escHtml(c.contact.username)}</div>
      </div>
      <div class="contact-actions">
        <button class="btn-revoke" onclick="revokeContact('${c.linkId}')" aria-label="Remove ${escHtml(name)}">Remove</button>
      </div>
    </div>
  `;
}

function renderPendingItem(c) {
  const name = c.contact.displayName || c.contact.username;
  const avatar = IconResolver.getAvatar(c.contact.username || c.contact.id);
  const isInbound = !c.isInitiator;
  return `
    <div class="contact-item">
      <div class="contact-avatar">
        <img src="${avatar}" alt="" style="width:100%;height:100%;border-radius:50%;filter:grayscale(0.6)">
      </div>
      <div class="contact-info">
        <div class="contact-name">${escHtml(name)}</div>
        <div class="contact-username">${isInbound ? 'Wants to connect' : 'Request sent'}</div>
      </div>
      <div class="contact-actions">
        ${isInbound ? `<button class="btn-accept" onclick="acceptContact('${c.linkId}')" aria-label="Accept request from ${escHtml(name)}">Accept</button>` : ''}
        <button class="btn-revoke" onclick="revokeContact('${c.linkId}')" aria-label="${isInbound ? 'Decline' : 'Cancel'}">
          ${isInbound ? 'Decline' : 'Cancel'}
        </button>
      </div>
    </div>
  `;
}

async function acceptContact(linkId) {
  try {
    await API.put(`/contacts/${linkId}/accept`, {});
    showToast('✅ Contact accepted!', 'success');
    await loadContacts();
  } catch (err) {
    showToast(`Failed: ${err.message}`, 'error');
  }
}

async function revokeContact(linkId) {
  if (!confirm('Remove this contact? This will stop all location sharing between you.')) return;
  try {
    await API.del(`/contacts/${linkId}`);
    showToast('Contact removed', 'info');
    await loadContacts();
  } catch (err) {
    showToast(`Failed: ${err.message}`, 'error');
  }
}

// ── Search ────────────────────────────────────────────
function searchUsers(q) {
  clearTimeout(_searchDebounce);
  if (q.length < 2) {
    document.getElementById('user-search-results').innerHTML = '';
    return;
  }
  _searchDebounce = setTimeout(() => _doSearch(q, 'user-search-results'), 400);
}

function modalSearchUsers(q) {
  clearTimeout(_searchDebounce);
  if (q.length < 2) {
    document.getElementById('modal-search-results').innerHTML = '';
    return;
  }
  _searchDebounce = setTimeout(() => _doSearch(q, 'modal-search-results'), 400);
}

async function _doSearch(q, targetId) {
  try {
    const users = await API.get(`/users/search?q=${encodeURIComponent(q)}`);
    const container = document.getElementById(targetId);
    if (!users.length) {
      container.innerHTML = '<div class="empty-state">No users found</div>';
      return;
    }
    container.innerHTML = users.map(u => {
      const name = u.displayName || u.username;
      const avatar = IconResolver.getAvatar(u.username || u.id);
      const alreadyLinked = AppState.contacts.some(c => c.contact.id === u.id);
      return `
        <div class="search-result-item">
          <div class="result-avatar">
            <img src="${avatar}" alt="" style="width:100%;height:100%;border-radius:50%">
          </div>
          <div class="result-info">
            <div class="result-name">${escHtml(name)}</div>
            <div class="result-sub">@${escHtml(u.username)}</div>
          </div>
          <button class="btn-add-contact" ${alreadyLinked ? 'disabled' : ''} onclick="sendContactRequest('${u.id}',this)" aria-label="Add ${escHtml(name)}">
            ${alreadyLinked ? 'Added' : 'Add'}
          </button>
        </div>
      `;
    }).join('');
  } catch (err) {
    // Silent fail
  }
}

async function sendContactRequest(targetUserId, btn) {
  btn.disabled = true;
  btn.textContent = 'Sending…';
  try {
    await API.post('/contacts/request', { targetUserId });
    btn.textContent = 'Sent ✓';
    showToast('Contact request sent!', 'success');
    await loadContacts();
  } catch (err) {
    btn.disabled = false;
    btn.textContent = 'Add';
    showToast(`Failed: ${err.message}`, 'error');
  }
}

// ── Groups ────────────────────────────────────────────
async function loadGroups() {
  try {
    const groups = await API.get('/contacts/groups');
    AppState.groups = groups;
    const list = document.getElementById('groups-list');
    if (!groups.length) {
      list.innerHTML = '<div class="empty-state" style="padding:12px">No groups yet</div>';
      return;
    }
    list.innerHTML = groups.map(g => `
      <div class="group-item">
        <div class="group-icon">👥</div>
        <div class="group-info">
          <div class="group-name">${escHtml(g.name)}</div>
          <div class="group-count">${g.members.length} member${g.members.length !== 1 ? 's' : ''}</div>
        </div>
        <button class="btn-icon" onclick="deleteGroup('${g.id}')" aria-label="Delete group ${escHtml(g.name)}" style="width:30px;height:30px">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>
        </button>
      </div>
    `).join('');
    updateSosGroupSelector();
  } catch (err) {
    // Silent fail
  }
}

function openCreateGroup() {
  // Populate member select from accepted contacts
  const acceptedContacts = AppState.contacts.filter(c => c.status === 'ACCEPTED');
  const memberSelect = document.getElementById('group-member-select');
  if (!acceptedContacts.length) {
    memberSelect.innerHTML = '<div class="empty-state">Add contacts first</div>';
  } else {
    memberSelect.innerHTML = acceptedContacts.map(c => {
      const name = c.contact.displayName || c.contact.username;
      const avatar = IconResolver.getAvatar(c.contact.username || c.contact.id);
      return `
        <div class="member-select-item" onclick="toggleMember(this,'${c.contact.id}')" data-id="${c.contact.id}" data-selected="false">
          <div class="result-avatar" style="width:32px;height:32px">
            <img src="${avatar}" alt="" style="width:100%;height:100%;border-radius:50%">
          </div>
          <span style="font-size:14px;flex:1;margin-left:8px">${escHtml(name)}</span>
          <div class="member-checkmark">
            <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="white" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>
          </div>
        </div>
      `;
    }).join('');
  }
  openModal('modal-create-group');
}

function toggleMember(el, userId) {
  const selected = el.dataset.selected === 'true';
  el.dataset.selected = (!selected).toString();
  el.classList.toggle('selected', !selected);
}

async function createGroup() {
  const name = document.getElementById('group-name').value.trim();
  if (!name) { showToast('Group name required', 'warn'); return; }

  const memberIds = Array.from(
    document.querySelectorAll('#group-member-select .member-select-item[data-selected="true"]')
  ).map(el => el.dataset.id);

  try {
    await API.post('/contacts/groups', { name, memberIds });
    showToast(`Group "${name}" created!`, 'success');
    closeModal('modal-create-group');
    document.getElementById('group-name').value = '';
    await loadGroups();
  } catch (err) {
    showToast(`Failed: ${err.message}`, 'error');
  }
}

async function deleteGroup(groupId) {
  if (!confirm('Delete this group?')) return;
  try {
    await API.del(`/contacts/groups/${groupId}`);
    showToast('Group deleted', 'info');
    await loadGroups();
  } catch (err) {
    showToast(`Failed: ${err.message}`, 'error');
  }
}

function updateSosGroupSelector() {
  const sel = document.getElementById('setting-sos-group');
  if (!sel) return;
  const current = sel.value;
  sel.innerHTML = '<option value="">All contacts</option>' +
    AppState.groups.map(g => `<option value="${g.id}">${escHtml(g.name)}</option>`).join('');
  sel.value = current;
}

function escHtml(str) {
  return (str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
