// @ts-nocheck
import Alpine from 'alpinejs';

window.adminApp = function () {
    /** Flatten a nested object into dot-notation key-value pairs */
    function flattenObject(obj, prefix) {
        const entries = [];
        for (const [k, v] of Object.entries(obj)) {
            const key = prefix ? prefix + '.' + k : k;
            if (v && typeof v === 'object' && !Array.isArray(v)) {
                entries.push(...flattenObject(v, key));
            } else {
                entries.push({ key, value: v == null ? '' : String(v) });
            }
        }
        return entries;
    }

    /** Rebuild a nested object from dot-notation key-value pairs */
    function unflattenEntries(entries) {
        const result = {};
        for (const { key, value } of entries) {
            const parts = key.split('.');
            let cur = result;
            for (let i = 0; i < parts.length - 1; i++) {
                if (!(parts[i] in cur) || typeof cur[parts[i]] !== 'object') {
                    cur[parts[i]] = {};
                }
                cur = cur[parts[i]];
            }
            cur[parts[parts.length - 1]] = value;
        }
        return result;
    }

    /** Build a tree-view display list from flat dot-notation entries */
    function buildTreeView(entries) {
        const rows = [];
        const seenGroups = new Set();
        for (let idx = 0; idx < entries.length; idx++) {
            const parts = entries[idx].key.split('.');
            for (let d = 0; d < parts.length - 1; d++) {
                const groupKey = parts.slice(0, d + 1).join('.');
                if (!seenGroups.has(groupKey)) {
                    seenGroups.add(groupKey);
                    rows.push({ type: 'group', label: parts[d], depth: d, idx: -1, path: groupKey });
                }
            }
            rows.push({ type: 'field', label: parts[parts.length - 1], depth: parts.length - 1, idx, path: entries[idx].key });
        }
        return rows;
    }

    return {
        authenticated: false,
        unrestricted: false,
        subject: '',
        scopes: [],
        scopeTemplates: {},
        allowedAuthenticSources: [],
        hasIdentityMapping: false,
        csrfToken: '',
        view: 'datastore',
        sidebarOpen: false,

        // Datastore state
        ds: {
            search: '',
            filterSource: '',
            filterScope: '',
            docs: [],
            loading: false,
            showCreate: false,
            showImport: false,
            creating: false,
            sortKey: '',
            sortDir: 'asc',
            createError: '',
            /** @type {number|null} */
            detailIdx: null,
            /** @type {number|null} */
            editIdx: null,
            editError: '',
            updating: false,
            edit: {
                identity_mapping_ids_str: '',
                document_data: []
            },
            create: {
                authentic_source: '',
                scope: '',
                document_id: '',
                identity_mapping_ids_str: '',
                document_data: []
            }
        },

        // Import view state
        importState: {
            docLoading: false,
            docResult: null,
            mapLoading: false,
            mapResult: null,
        },

        // Identity mapping state
        im: {
            search: '',
            filterSource: '',
            mappings: [],
            loading: false,
            showCreate: false,
            showImport: false,
            creating: false,
            createError: '',
            sortKey: '',
            sortDir: 'asc',
            editIdx: null,
            editError: '',
            updating: false,
            create: {
                authentic_source: '',
                authentic_source_person_id: '',
                attributes: [
                    { key: 'family_name', value: '' },
                    { key: 'given_name', value: '' },
                    { key: 'birth_date', value: '' },
                ],
                attributes_json: '{}',
                newFieldKey: ''
            },
            createTab: 'editor',
            editTab: 'editor',
            edit: {
                authentic_source: '',
                authentic_source_person_id: '',
                attributes: [],
                attributes_json: '{}',
                newFieldKey: ''
            }
        },

        /** Show a toast notification instead of alert() */
        showToast(message, type = 'info') {
            const container = document.getElementById('toast-container');
            if (!container) return;
            const toast = document.createElement('div');
            toast.className = 'toast align-items-center text-bg-' + type + ' border-0 show';
            toast.setAttribute('role', 'alert');
            toast.innerHTML = '<div class="d-flex"><div class="toast-body">' + message.replace(/</g, '&lt;') + '</div><button type="button" class="btn-close btn-close-white me-2 m-auto" aria-label="Close"></button></div>';
            toast.querySelector('.btn-close').addEventListener('click', () => toast.remove());
            container.appendChild(toast);
            setTimeout(() => toast.remove(), 5000);
        },

        /** Fetch wrapper that adds CSRF token header to mutating requests. */
        apiFetch(url, opts = {}) {
            opts.credentials = 'same-origin';
            const method = (opts.method || 'GET').toUpperCase();
            if (method !== 'GET' && method !== 'HEAD' && this.csrfToken) {
                opts.headers = { ...opts.headers, 'X-CSRF-Token': this.csrfToken };
            }
            return fetch(url, opts);
        },

        async init() {
            try {
                const resp = await fetch('/ui/status', { credentials: 'same-origin' });
                const data = await resp.json();
                if (data.authenticated) {
                    this.authenticated = true;
                    this.subject = data.subject || '';
                    this.scopes = (data.scopes || []).sort();
                    this.scopeTemplates = data.scope_templates || {};
                    this.allowedAuthenticSources = (data.allowed_authentic_sources || []).sort();
                    this.hasIdentityMapping = data.has_identity_mapping || false;
                    this.unrestricted = data.unrestricted || false;
                    this.csrfToken = data.csrf_token || '';
                    this.searchDocuments();
                }
            } catch (e) {
                // not authenticated
            }
        },

        logout() {
            fetch('/ui/logout', { method: 'POST' })
                .then(resp => resp.json())
                .then(data => {
                    this.authenticated = false;
                    if (data.logout_url) {
                        window.location.href = data.logout_url;
                    }
                })
                .catch(() => {
                    this.authenticated = false;
                });
        },

        switchView(v) {
            this.view = v;
            this.importState.docResult = null;
            this.importState.mapResult = null;
            if (v === 'datastore') this.searchDocuments();
            if (v === 'identity') this.searchMappings();
        },

        treeView(entries) { return buildTreeView(entries); },

        /** Remove all entries under a group prefix */
        removeGroup(entries, groupPath) {
            const prefix = groupPath + '.';
            for (let i = entries.length - 1; i >= 0; i--) {
                if (entries[i].key === groupPath || entries[i].key.startsWith(prefix)) {
                    entries.splice(i, 1);
                }
            }
        },

        /** Add a new empty field inside a group, inserted after the last child */
        addChildField(entries, groupPath) {
            const prefix = groupPath + '.';
            let lastIdx = -1;
            for (let i = 0; i < entries.length; i++) {
                if (entries[i].key.startsWith(prefix)) {
                    lastIdx = i;
                }
            }
            entries.splice(lastIdx + 1, 0, { key: prefix, value: '' });
        },

        /** Rename a field's leaf segment (used for newly added child fields) */
        renameField(entries, idx, name) {
            const entry = entries[idx];
            const parts = entry.key.split('.');
            parts[parts.length - 1] = name.trim();
            entry.key = parts.join('.');
        },

        /** Convert a flat field into a group with an empty child */
        promoteToGroup(entries, idx) {
            const key = entries[idx].key;
            entries[idx].key = key + '.';
        },

        formatDate(d) {
            if (!d) return '-';
            try {
                return new Date(d).toISOString();
            } catch {
                return d;
            }
        },

        // --- Datastore ---

        sortDocs(key) {
            if (this.ds.sortKey === key) {
                this.ds.sortDir = this.ds.sortDir === 'asc' ? 'desc' : 'asc';
            } else {
                this.ds.sortKey = key;
                this.ds.sortDir = 'asc';
            }
            const dir = this.ds.sortDir === 'asc' ? 1 : -1;
            const accessors = {
                document_id: d => d.meta?.document_id || '',
                authentic_source: d => d.meta?.authentic_source || '',
                scope: d => d.meta?.scope || '',
                created_at: d => d.meta?.created_at || '',
            };
            const accessor = accessors[key];
            this.ds.docs.sort((a, b) => {
                const va = accessor(a), vb = accessor(b);
                return va < vb ? -dir : va > vb ? dir : 0;
            });
        },

        openCreateDocument() {
            this.ds.create = {
                authentic_source: '',
                scope: '',
                document_id: '',
                identity_mapping_ids_str: '',
                document_data: []
            };
            this.ds.createError = '';
            this.ds.showCreate = true;
            this.$nextTick(() => {
                if (this.allowedAuthenticSources.length === 1) {
                    this.ds.create.authentic_source = this.allowedAuthenticSources[0];
                }
                if (this.scopes.length === 1) {
                    this.ds.create.scope = this.scopes[0];
                    this.onScopeChange();
                }
            });
        },

        onScopeChange() {
            const scope = this.ds.create.scope;
            const template = this.scopeTemplates[scope];
            if (template && Object.keys(template).length > 0) {
                this.ds.create.document_data = flattenObject(template, '');
                this.ds.create.document_data_json = JSON.stringify(template, null, 2);
            }
        },

        async _doDocumentImport(file) {
            const text = await file.text();
            const data = JSON.parse(text);
            const resp = await this.apiFetch('/api/v1/datastore/bulk', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ documents: data }),
                credentials: 'same-origin'
            });
            if (!resp.ok) {
                const err = await resp.json().catch(() => ({}));
                throw new Error(err.error || err.detail || resp.statusText);
            }
            const result = await resp.json().catch(() => ({}));
            return result.count || 0;
        },

        async importDocument(event) {
            const file = event.target.files[0];
            event.target.value = '';
            if (!file) return;
            try {
                const count = await this._doDocumentImport(file);
                this.showToast('Imported ' + count + ' document' + (count !== 1 ? 's' : ''), 'success');
                this.searchDocuments();
            } catch (e) {
                this.showToast('Import failed: ' + e.message, 'danger');
            }
        },

        async importDocumentFromView(event) {
            const file = event.target.files[0];
            event.target.value = '';
            if (!file) return;
            this.importState.docLoading = true;
            this.importState.docResult = null;
            try {
                const count = await this._doDocumentImport(file);
                this.importState.docResult = { success: true, message: 'Successfully imported ' + count + ' document' + (count !== 1 ? 's' : '') + ' from ' + file.name };
            } catch (e) {
                this.importState.docResult = { success: false, message: 'Import failed: ' + e.message };
            }
            this.importState.docLoading = false;
        },

        async searchDocuments() {
            this.ds.loading = true;
            try {
                const params = new URLSearchParams();
                if (this.ds.search) params.set('search', this.ds.search);
                if (this.ds.filterSource) params.set('authentic_source', this.ds.filterSource);
                if (this.ds.filterScope) params.set('scope', this.ds.filterScope);
                const resp = await this.apiFetch('/api/v1/datastore/search?' + params.toString(), {
                    credentials: 'same-origin'
                });
                const data = await resp.json();
                this.ds.docs = data.data || [];
            } catch (e) {
                console.error('search documents error', e);
            }
            this.ds.loading = false;
        },

        toggleDocDetail(idx) {
            this.ds.detailIdx = this.ds.detailIdx === idx ? null : idx;
        },

        async createDocument() {
            this.ds.creating = true;
            this.ds.createError = '';
            try {
                if (!this.ds.create.authentic_source.trim()) {
                    this.ds.createError = 'Authentic Source is required';
                    this.ds.creating = false;
                    return;
                }
                if (!this.ds.create.scope.trim()) {
                    this.ds.createError = 'Scope is required';
                    this.ds.creating = false;
                    return;
                }
                const docData = unflattenEntries(this.ds.create.document_data);
                const ids = this.ds.create.identity_mapping_ids_str
                    ? this.ds.create.identity_mapping_ids_str.split(',').map(s => s.trim()).filter(Boolean)
                    : [];
                if (ids.length === 0) {
                    this.ds.createError = 'At least one Identity Mapping ID is required';
                    this.ds.creating = false;
                    return;
                }
                const meta = {
                    authentic_source: this.ds.create.authentic_source,
                    scope: this.ds.create.scope,
                    ...(this.ds.create.document_id ? { document_id: this.ds.create.document_id } : {}),
                };
                const body = {
                    meta,
                    identity_mapping_ids: ids,
                    document_data: docData
                };
                const resp = await this.apiFetch('/api/v1/datastore', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body),
                    credentials: 'same-origin'
                });
                if (!resp.ok) {
                    const text = await resp.text();
                    throw new Error(text || resp.statusText);
                }
                this.ds.showCreate = false;
                this.ds.create = { authentic_source: '', scope: '', document_id: '', identity_mapping_ids_str: '', document_data: [] };
                this.searchDocuments();
            } catch (e) {
                this.ds.createError = 'Failed: ' + e.message;
            }
            this.ds.creating = false;
        },

        async deleteDocument(doc) {
            if (!confirm('Delete document ' + (doc.meta?.document_id || '') + '?')) return;
            try {
                await this.apiFetch('/api/v1/datastore', {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        authentic_source: doc.meta?.authentic_source,
                        scope: doc.meta?.scope,
                        document_id: doc.meta?.document_id
                    }),
                    credentials: 'same-origin'
                });
                this.searchDocuments();
            } catch (e) {
                alert('Delete failed: ' + e.message);
            }
        },

        /** @param {number} idx */
        openEditDocument(idx) {
            const doc = this.ds.docs[idx];
            const dd = doc.document_data || {};
            this.ds.edit = {
                identity_mapping_ids_str: (doc.identity_mapping_ids || []).join(', '),
                document_data: flattenObject(dd, '')
            };
            this.ds.editError = '';
            this.ds.editIdx = idx;
        },

        async updateDocument() {
            this.ds.updating = true;
            this.ds.editError = '';
            const doc = this.ds.docs[/** @type {number} */ (this.ds.editIdx)];
            try {
                const docData = unflattenEntries(this.ds.edit.document_data);
                const ids = this.ds.edit.identity_mapping_ids_str
                    ? this.ds.edit.identity_mapping_ids_str.split(',').map(s => s.trim()).filter(Boolean)
                    : [];
                if (ids.length === 0) {
                    this.ds.editError = 'At least one Identity Mapping ID is required';
                    this.ds.updating = false;
                    return;
                }
                const body = {
                    meta: {
                        authentic_source: doc.meta?.authentic_source,
                        scope: doc.meta?.scope,
                        document_id: doc.meta?.document_id,
                    },
                    identity_mapping_ids: ids,
                    document_data: docData
                };
                const resp = await this.apiFetch('/api/v1/datastore', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body),
                    credentials: 'same-origin'
                });
                if (!resp.ok) {
                    const text = await resp.text();
                    throw new Error(text || resp.statusText);
                }
                this.ds.editIdx = null;
                this.searchDocuments();
            } catch (e) {
                this.ds.editError = 'Failed: ' + e.message;
            }
            this.ds.updating = false;
        },

        // --- Identity Mappings ---

        sortMappings(key) {
            if (this.im.sortKey === key) {
                this.im.sortDir = this.im.sortDir === 'asc' ? 'desc' : 'asc';
            } else {
                this.im.sortKey = key;
                this.im.sortDir = 'asc';
            }
            const dir = this.im.sortDir === 'asc' ? 1 : -1;
            const accessors = {
                person_id: m => m.authentic_source_person_id || '',
                authentic_source: m => m.authentic_source || '',
                attributes: m => JSON.stringify(m.attributes || {}),
                created_at: m => m.created_at || '',
            };
            const accessor = accessors[key];
            this.im.mappings.sort((a, b) => {
                const va = accessor(a), vb = accessor(b);
                return va < vb ? -dir : va > vb ? dir : 0;
            });
        },

        async _doMappingImport(file) {
            const text = await file.text();
            const data = JSON.parse(text);
            const mappings = {};
            for (const [key, val] of Object.entries(data)) {
                if (Array.isArray(val)) {
                    val.forEach((m, i) => { mappings[key + '_' + i] = m; });
                } else {
                    mappings[key] = val;
                }
            }
            const resp = await this.apiFetch('/api/v1/identity/mapping/bulk', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mappings }),
                credentials: 'same-origin'
            });
            if (!resp.ok) {
                const err = await resp.json().catch(() => ({}));
                throw new Error(err.error || err.detail || resp.statusText);
            }
            const result = await resp.json().catch(() => ({}));
            return result.count || 0;
        },

        async importMapping(event) {
            const file = event.target.files[0];
            event.target.value = '';
            if (!file) return;
            try {
                const count = await this._doMappingImport(file);
                this.showToast('Imported ' + count + ' mapping' + (count !== 1 ? 's' : ''), 'success');
                this.searchMappings();
            } catch (e) {
                this.showToast('Import failed: ' + e.message, 'danger');
            }
        },

        async importMappingFromView(event) {
            const file = event.target.files[0];
            event.target.value = '';
            if (!file) return;
            this.importState.mapLoading = true;
            this.importState.mapResult = null;
            try {
                const count = await this._doMappingImport(file);
                this.importState.mapResult = { success: true, message: 'Successfully imported ' + count + ' mapping' + (count !== 1 ? 's' : '') + ' from ' + file.name };
            } catch (e) {
                this.importState.mapResult = { success: false, message: 'Import failed: ' + e.message };
            }
            this.importState.mapLoading = false;
        },

        async searchMappings() {
            this.im.loading = true;
            try {
                const params = new URLSearchParams();
                if (this.im.search) params.set('search', this.im.search);
                if (this.im.filterSource) params.set('authentic_source', this.im.filterSource);
                const resp = await this.apiFetch('/api/v1/identity/mapping/search?' + params.toString(), {
                    credentials: 'same-origin'
                });
                const data = await resp.json();
                this.im.mappings = data.data || [];
            } catch (e) {
                console.error('search mappings error', e);
            }
            this.im.loading = false;
        },

        openCreateMapping() {
            this.im.create = {
                authentic_source: '',
                authentic_source_person_id: '',
                attributes: [
                    { key: 'family_name', value: '' },
                    { key: 'given_name', value: '' },
                    { key: 'birth_date', value: '' },
                ],
                attributes_json: '{}',
                newFieldKey: ''
            };
            this.im.createTab = 'editor';
            this.im.createError = '';
            this.im.showCreate = true;
            this.$nextTick(() => {
                if (this.allowedAuthenticSources.length === 1) {
                    this.im.create.authentic_source = this.allowedAuthenticSources[0];
                }
            });
        },

        addMappingAttribute() {
            const key = this.im.create.newFieldKey.trim();
            if (!key) return;
            this.im.create.attributes.push({ key, value: '' });
            this.im.create.newFieldKey = '';
        },

        async createMapping() {
            this.im.creating = true;
            this.im.createError = '';
            try {
                if (!this.im.create.authentic_source.trim()) {
                    this.im.createError = 'Authentic Source is required';
                    this.im.creating = false;
                    return;
                }
                let attrs;
                if (this.im.createTab === 'json') {
                    attrs = JSON.parse(this.im.create.attributes_json);
                } else {
                    attrs = {};
                    for (const a of this.im.create.attributes.filter(a => a.key.trim())) {
                        attrs[a.key.trim()] = a.value;
                    }
                }
                const body = {
                    authentic_source: this.im.create.authentic_source,
                    authentic_source_person_id: this.im.create.authentic_source_person_id,
                    attributes: attrs
                };
                const resp = await this.apiFetch('/api/v1/identity/mapping', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body),
                    credentials: 'same-origin'
                });
                if (!resp.ok) {
                    const text = await resp.text();
                    throw new Error(text || resp.statusText);
                }
                this.im.showCreate = false;
                this.im.create = {
                    authentic_source: '', authentic_source_person_id: '',
                    attributes: [
                        { key: 'family_name', value: '' },
                        { key: 'given_name', value: '' },
                        { key: 'birth_date', value: '' },
                    ],
                    attributes_json: '{}',
                    newFieldKey: ''
                };
                this.searchMappings();
            } catch (e) {
                this.im.createError = 'Failed: ' + e.message;
            }
            this.im.creating = false;
        },

        startEditMapping(idx) {
            const m = this.im.mappings[idx];
            this.im.editIdx = idx;
            this.im.editError = '';
            const attrs = m.attributes || {};
            this.im.editTab = 'editor';
            this.im.edit = {
                authentic_source: m.authentic_source,
                authentic_source_person_id: m.authentic_source_person_id,
                attributes: Object.entries(attrs).map(([key, value]) => ({ key, value: String(value) })),
                attributes_json: JSON.stringify(attrs, null, 2),
                newFieldKey: ''
            };
        },

        addEditMappingAttribute() {
            const key = this.im.edit.newFieldKey.trim();
            if (!key) return;
            this.im.edit.attributes.push({ key, value: '' });
            this.im.edit.newFieldKey = '';
        },

        switchImCreateTab(tab) {
            if (tab === this.im.createTab) return;
            if (tab === 'json') {
                const attrs = {};
                for (const a of this.im.create.attributes) { attrs[a.key] = a.value; }
                this.im.create.attributes_json = JSON.stringify(attrs, null, 2);
            } else {
                try {
                    const obj = JSON.parse(this.im.create.attributes_json);
                    this.im.create.attributes = Object.entries(obj).map(([key, value]) => ({ key, value: String(value) }));
                } catch { /* keep current */ }
            }
            this.im.createTab = tab;
        },

        switchImEditTab(tab) {
            if (tab === this.im.editTab) return;
            if (tab === 'json') {
                const attrs = {};
                for (const a of this.im.edit.attributes) { attrs[a.key] = a.value; }
                this.im.edit.attributes_json = JSON.stringify(attrs, null, 2);
            } else {
                try {
                    const obj = JSON.parse(this.im.edit.attributes_json);
                    this.im.edit.attributes = Object.entries(obj).map(([key, value]) => ({ key, value: String(value) }));
                } catch { /* keep current */ }
            }
            this.im.editTab = tab;
        },

        async updateMapping() {
            this.im.updating = true;
            this.im.editError = '';
            try {
                let attrs;
                if (this.im.editTab === 'json') {
                    attrs = JSON.parse(this.im.edit.attributes_json);
                } else {
                    attrs = {};
                    for (const a of this.im.edit.attributes.filter(a => a.key.trim())) {
                        attrs[a.key.trim()] = a.value;
                    }
                }
                const body = {
                    authentic_source: this.im.edit.authentic_source,
                    authentic_source_person_id: this.im.edit.authentic_source_person_id,
                    attributes: attrs
                };
                const resp = await this.apiFetch('/api/v1/identity/mapping', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body),
                    credentials: 'same-origin'
                });
                if (!resp.ok) {
                    const text = await resp.text();
                    throw new Error(text || resp.statusText);
                }
                this.im.editIdx = null;
                this.searchMappings();
            } catch (e) {
                this.im.editError = 'Failed: ' + e.message;
            }
            this.im.updating = false;
        },

        async deleteMapping(m) {
            if (!confirm('Delete mapping for ' + (m.authentic_source_person_id || '') + '?')) return;
            try {
                await this.apiFetch('/api/v1/identity/mapping', {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        authentic_source: m.authentic_source,
                        authentic_source_person_id: m.authentic_source_person_id
                    }),
                    credentials: 'same-origin'
                });
                this.searchMappings();
            } catch (e) {
                alert('Delete failed: ' + e.message);
            }
        }
    };
};

Alpine.start();
