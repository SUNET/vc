import Alpine from 'alpinejs';

window.adminApp = function () {
    return {
        authenticated: false,
        givenName: '',
        view: 'datastore',

        // Datastore state
        ds: {
            search: '',
            docs: [],
            loading: false,
            showCreate: false,
            creating: false,
            createError: '',
            detailIdx: null,
            create: {
                authentic_source: '',
                scope: '',
                document_id: '',
                identity_mapping_ids_str: '',
                document_data_str: '{}'
            }
        },

        // Identity mapping state
        im: {
            search: '',
            mappings: [],
            loading: false,
            showCreate: false,
            creating: false,
            createError: '',
            editIdx: null,
            editError: '',
            updating: false,
            create: {
                authentic_source: '',
                authentic_source_person_id: '',
                attributes_str: '{}'
            },
            edit: {
                authentic_source: '',
                authentic_source_person_id: '',
                attributes_str: '{}'
            }
        },

        async init() {
            try {
                const resp = await fetch('/ui/status', { credentials: 'same-origin' });
                const data = await resp.json();
                if (data.authenticated) {
                    this.authenticated = true;
                    this.givenName = data.given_name || '';
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
            if (v === 'datastore' && this.ds.docs.length === 0) this.searchDocuments();
            if (v === 'identity' && this.im.mappings.length === 0) this.searchMappings();
        },

        formatDate(d) {
            if (!d) return '-';
            try {
                return new Date(d).toLocaleString();
            } catch {
                return d;
            }
        },

        // --- Datastore ---

        async searchDocuments() {
            this.ds.loading = true;
            try {
                const params = new URLSearchParams();
                if (this.ds.search) params.set('search', this.ds.search);
                const resp = await fetch('/api/v1/datastore/search?' + params.toString(), {
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
                let docData;
                try {
                    docData = JSON.parse(this.ds.create.document_data_str);
                } catch {
                    this.ds.createError = 'Invalid JSON in Document Data';
                    this.ds.creating = false;
                    return;
                }
                const ids = this.ds.create.identity_mapping_ids_str
                    ? this.ds.create.identity_mapping_ids_str.split(',').map(s => s.trim()).filter(Boolean)
                    : [];
                const body = {
                    meta: {
                        authentic_source: this.ds.create.authentic_source,
                        scope: this.ds.create.scope,
                        document_id: this.ds.create.document_id
                    },
                    identity_mapping_ids: ids,
                    document_data: docData
                };
                const resp = await fetch('/api/v1/datastore', {
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
                this.ds.create = { authentic_source: '', scope: '', document_id: '', identity_mapping_ids_str: '', document_data_str: '{}' };
                this.searchDocuments();
            } catch (e) {
                this.ds.createError = 'Failed: ' + e.message;
            }
            this.ds.creating = false;
        },

        async deleteDocument(doc) {
            if (!confirm('Delete document ' + (doc.meta?.document_id || '') + '?')) return;
            try {
                await fetch('/api/v1/datastore', {
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

        // --- Identity Mappings ---

        async searchMappings() {
            this.im.loading = true;
            try {
                const params = new URLSearchParams();
                if (this.im.search) params.set('search', this.im.search);
                const resp = await fetch('/api/v1/identity/mapping/search?' + params.toString(), {
                    credentials: 'same-origin'
                });
                const data = await resp.json();
                this.im.mappings = data.data || [];
            } catch (e) {
                console.error('search mappings error', e);
            }
            this.im.loading = false;
        },

        async createMapping() {
            this.im.creating = true;
            this.im.createError = '';
            try {
                let attrs;
                try {
                    attrs = JSON.parse(this.im.create.attributes_str);
                } catch {
                    this.im.createError = 'Invalid JSON in Attributes';
                    this.im.creating = false;
                    return;
                }
                const body = {
                    authentic_source: this.im.create.authentic_source,
                    authentic_source_person_id: this.im.create.authentic_source_person_id,
                    attributes: attrs
                };
                const resp = await fetch('/api/v1/identity/mapping', {
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
                this.im.create = { authentic_source: '', authentic_source_person_id: '', attributes_str: '{}' };
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
            this.im.edit = {
                authentic_source: m.authentic_source,
                authentic_source_person_id: m.authentic_source_person_id,
                attributes_str: JSON.stringify(m.attributes || {}, null, 2)
            };
        },

        async updateMapping() {
            this.im.updating = true;
            this.im.editError = '';
            try {
                let attrs;
                try {
                    attrs = JSON.parse(this.im.edit.attributes_str);
                } catch {
                    this.im.editError = 'Invalid JSON in Attributes';
                    this.im.updating = false;
                    return;
                }
                const body = {
                    authentic_source: this.im.edit.authentic_source,
                    authentic_source_person_id: this.im.edit.authentic_source_person_id,
                    attributes: attrs
                };
                const resp = await fetch('/api/v1/identity/mapping', {
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
                await fetch('/api/v1/identity/mapping', {
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
