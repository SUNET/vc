const baseUrl = window.location.origin;

const getElementById = (id) => document.getElementById(id);

const removeElementById = (id) => {
    getElementById(id)?.remove();
};

const clearContainer = (id) => {
    //console.debug(`Clearing element : ${id}`);
    const element = getElementById(id);
    if (element) {
        element.innerHTML = "";
    }
};

const clearAllContentContainers = () => {
    clearContainer("login-container");
    clearContainer("article-container");
};

function displayAElement(id) {
    getElementById(id).style.display = 'inline'; // Use 'inline' for <a>-element
}

function hideAElement(id) {
    getElementById(id).style.display = 'none';
}

function displayDiv(id) {
    getElementById(id).style.display = 'flex';//'block';
}

function hideDiv(id) {
    getElementById(id).style.display = 'none';
}

function hideSecureMenyItems() {
    hideDiv('navbar-start-div');
    hideAElement("do-logout-btn");
    displayAElement("show-login-form-btn");
}

function displaySecureMenyItems() {
    displayDiv('navbar-start-div');
    displayAElement("do-logout-btn");
    hideAElement("show-login-form-btn");
}

/**
 * @returns {string} containing UUID v4
 */
const generateUUID = () => {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        var r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
};

const toogleThemeDarkLight = () => {
    const htmlElement = document.documentElement;
    if (htmlElement.className === "theme-light") {
        htmlElement.className = "theme-dark";
    } else {
        htmlElement.className = "theme-light";
    }
};

const generateArticleIDBasis = () => {
    const uuid = generateUUID();
    const articleID = "article-" + uuid;

    return {
        uuid, articleID,
    };
};

function isLoggedIn() {
    const cookie = document.cookie;
    if (cookie && cookie.match(/vc_ui_auth_session=(.*?)(;|$)/)[1]) {
        console.debug("User is authenticated");
        return true;
    }
    console.debug("User is not authenticated");
    //Note: Expire time for cookie is handled by the browser and is removed from document.cookie when expired

    return false;
}

const addNewRequestResponseArticleToContainer = (articleHeaderText) => {
    const articleIDBasis = generateArticleIDBasis();
    const uuid = articleIDBasis.uuid;
    const articleID = articleIDBasis.articleID;

    const buildDiv = (title, idExtension) => {
        const div = document.createElement("div");
        div.id = `article-${idExtension}-${uuid}`;
        div.innerHTML = `<h4>${title}</h4><pre class="box">Loading...</pre>`;
        return div;
    };

    const bodyChildren = {
        reqMetaDiv: buildDiv('Request meta', 'req-meta'),
        errorDiv: buildDiv('Error', 'error'),
        respMetaDiv: buildDiv('Respons meta', 'resp-meta'),
        payloadDiv: buildDiv('Payload', 'payload'),
    };

    const articleDiv = buildArticle(articleID, articleHeaderText, [bodyChildren.reqMetaDiv, bodyChildren.errorDiv, bodyChildren.respMetaDiv, bodyChildren.payloadDiv]);
    const articleContainer = getElementById('article-container');
    articleContainer.prepend(articleDiv);
    return bodyChildren;
};

function buildResponseMeta(response) {
    const status = response.status; //
    const statusText = response.statusText;
    //const respUrl = response.url;
    const contentType = response.headers.get('Content-Type');
    return `Response status: ${status} (${statusText}), Content-Type: ${contentType}`;
}

function updateTextContentInChildPreTagFor(parentElement, textContent) {
    const preElement = parentElement.querySelector("pre");
    preElement.textContent = textContent ?? "";
}

function handleErrorInArticle(err, elements) {
    console.error("Error fetching data: ", err.message);

    const errorPreElement = elements.errorDiv.querySelector("pre");
    errorPreElement.style.color = "red";
    updateTextContentInChildPreTagFor(elements.errorDiv, err.name + " " + err.message);
    updateTextContentInChildPreTagFor(elements.respMetaDiv, "");
    updateTextContentInChildPreTagFor(elements.payloadDiv, "");
}

function openModalQR() {
    const modal = document.getElementById("qrModal");
    modal.classList.add("is-active");
}

function closeModalQR() {
    const modal = document.getElementById("qrModal");
    modal.classList.remove("is-active");
}

async function doFetchAPICallAndHandleResult(url, options, elements) {
    try {
        //TODO(mk): add timeout on clientside for fetch
        const response = await fetch(url, options);
        const jsonBody = await response.json();
        //console.debug(jsonBody);

        if (!response.ok) {
            if (response.status === 401) {
                // Not auth/session expired
                clearAllContentContainers();
                hideSecureMenyItems();
                return;
            }
            throw new Error(`HTTP error! status: ${response.status}, method: ${response.method}, url: ${url}, body: ${JSON.stringify(jsonBody, null, 2)}`);
        }

        updateTextContentInChildPreTagFor(elements.respMetaDiv, buildResponseMeta(response));
        updateTextContentInChildPreTagFor(elements.errorDiv, "");
        updateTextContentInChildPreTagFor(elements.payloadDiv, JSON.stringify(jsonBody, null, 2));

        //TODO(mk): refactor this quick and dirty solution to display the QR code in a modal for /notification before the standard response article
        if (url.href.includes("notification") && jsonBody && jsonBody.data && jsonBody.data.base64_image) {
            const base64Image = jsonBody.data.base64_image;
            const imgElement = document.getElementById("qrCodeImage");
            imgElement.src = "data:image/png;base64," + base64Image;
            openModalQR();
        }

    } catch (err) {
        handleErrorInArticle(err, elements);
    }
}

async function getAndDisplayInArticleContainerFor(path, articleHeaderText) {
    const url = new URL(path, baseUrl);
    //console.debug("Call to getAndDisplayInArticleContainerFor: " + url);

    const elements = addNewRequestResponseArticleToContainer(articleHeaderText);

    const headers = {
        'Accept': 'application/json',
    };

    const options = {
        method: `GET`, headers: headers,
    };

    updateTextContentInChildPreTagFor(elements.reqMetaDiv, `${JSON.stringify(options, null, 2)}`)

    await doFetchAPICallAndHandleResult(url, options, elements);
}

async function postAndDisplayInArticleContainerFor(path, requestBody, articleHeaderText) {
    const url = new URL(path, baseUrl);
    //console.debug("Call to postAndDisplayInArticleContainerFor: " + url);

    const elements = addNewRequestResponseArticleToContainer(articleHeaderText);

    const headers = {
        'Accept': 'application/json', 'Content-Type': 'application/json; charset=utf-8',
    };
    const options = {
        method: `POST`, headers: headers, body: JSON.stringify(requestBody),
    };

    updateTextContentInChildPreTagFor(elements.reqMetaDiv, `${JSON.stringify(options, null, 2)}`)

    await doFetchAPICallAndHandleResult(url, options, elements);
}

const createMock = () => {
    //console.debug("createMock");

    const scopeElement = getElementById("scope-select");
    const authenticSourceElement = getElementById("authentic-source-input");
    const authenticSourcePersonIdElement = getElementById("authentic_source_person_id-input");
    const identitySchemaNameElement = getElementById("identity-schema-name");

    const postBody = {
        scope: scopeElement.value,
        authentic_source: authenticSourceElement.value,
        authentic_source_person_id: authenticSourcePersonIdElement.value,
        identity_schema_name: identitySchemaNameElement.value,
    };

    postAndDisplayInArticleContainerFor("/secure/mockas/mock/next", postBody, "Upload new mock document result");
};

const postDocumentList = () => {
    //console.debug("postDocumentList");
    const path = "/secure/apigw/document/list";
    const articleHeaderText = "List documents result";

    const authenticSourceElement = getElementById("authentic-source-input");
    const authenticSourcePersonIdElement = getElementById("authentic_source_person_id-input");
    const identitySchemaName = getElementById("identity-schema-name");

    const documentListRequest = {
        authentic_source: authenticSourceElement.value,
        identity_mapping_id: authenticSourcePersonIdElement.value,
        scope: getElementById("scope-select").value
    };

    postAndDisplayInArticleContainerFor(path, documentListRequest, articleHeaderText);
};

const updateMockAndListButtons = () => {
    const input = getElementById('authentic_source_person_id-input');
    const mockBtn = getElementById('create-mock-btn');
    const documentListBtn = getElementById('post-document-list-btn');

    //TODO(mk): Validate input values?
    mockBtn.disabled = !(input.value);
    documentListBtn.disabled = !(input.value);
};

/** Builds an article with custom body children but does not add it to the DOM
 *
 * @param articleID required
 * @param articleHeaderText required
 * @param bodyChildrenElementArray Can be null or empty. Is inserted in as children to article in same order as array in
 the html
 * @returns {HTMLElement} article
 */
const buildArticle = (articleID, articleHeaderText, bodyChildrenElementArray) => {
    const expandCollapseButton = document.createElement('button');
    expandCollapseButton.onclick = () => toggleExpandCollapseArticle(articleID);
    expandCollapseButton.classList.add("button", "is-dark");
    expandCollapseButton.textContent = "Collapse/Expand";
    expandCollapseButton.ariaLabel = "toggle collapse/expand";

    const removeButton = document.createElement('button');
    removeButton.onclick = () => removeElementById(articleID);
    removeButton.classList.add("delete", "is-medium");
    removeButton.ariaLabel = "delete";

    const pElement = document.createElement('p');
    pElement.textContent = articleHeaderText ? articleHeaderText : "";

    const divHeader = document.createElement('div');
    divHeader.classList.add("message-header");
    divHeader.prepend(pElement, expandCollapseButton, removeButton);

    const divBody = document.createElement('div');
    divBody.classList.add("message-body");
    if (bodyChildrenElementArray != null && bodyChildrenElementArray.length !== 0) {
        // Add to body in the same order as the elements in the array
        for (const bodyChildElement of bodyChildrenElementArray.reverse()) {
            divBody.prepend(bodyChildElement);
        }
    }

    const article = document.createElement("article");
    article.id = articleID;
    article.classList.add("message", "is-dark", "box");
    article.prepend(divHeader, divBody);

    return article;
};

async function doLogin() {
    const url = new URL("/login", baseUrl);
    //console.debug("doLogin for url: " + url);

    const doLoginButton = getElementById("do-login-btn");
    doLoginButton.disabled = true;

    const usernameInput = getElementById("username-input");
    const username = usernameInput.value;
    usernameInput.disabled = true;

    const passwordInput = getElementById("password-input");
    const password = passwordInput.value;
    passwordInput.disabled = true;

    const postBody = {
        username: username, password: password,
    };

    let request = {
        method: 'POST', headers: {
            'Accept': 'application/json', 'Content-Type': 'application/json',
        }, body: JSON.stringify(postBody),
    };

    let authOK = false;

    try {
        const response = await fetch(url, request);

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}, method: ${request.method}, url: ${url}, headers: ${JSON.stringify(response.headers)}`);
        }

        // const jsonBody = await response.json();
        // console.debug(jsonBody);
        authOK = true;
    } catch (err) {
        console.debug("Login attempt failed: ", err.message);
    }

    if (authOK) {
        clearContainer("login-container");
        displaySecureMenyItems();
        //TODO(mk): display current logged in user in UI?
        addSearchDocumentsFormArticleToContainer();
    } else {
        usernameInput.disabled = false;
        passwordInput.disabled = false;
        doLoginButton.disabled = false;
        //TODO(mk): if auth!=ok display some info/error message...
    }
}

const addUploadFormArticleToContainer = () => {
    const textareaId = generateUUID();
    const buildUploadFormElements = (textareaId) => {
        const textarea = document.createElement("textarea");
        textarea.id = textareaId;
        textarea.classList.add("textarea");
        textarea.rows = 20;
        textarea.placeholder = "Document as json";

        const submitButton = document.createElement('button');
        submitButton.id = generateUUID();
        submitButton.classList.add('button', 'is-link');
        submitButton.textContent = 'Upload';

        const doUpload = (textarea, submitButton) => {
            submitButton.disabled = true;
            const text = textarea.value;
            textarea.disabled = true;
            const jsonObj = JSON.parse(text);
            postAndDisplayInArticleContainerFor("/secure/apigw/upload", jsonObj, "Upload document result");
        };
        submitButton.onclick = () => doUpload(textarea, submitButton);

        const buttonControl = document.createElement('div');
        buttonControl.classList.add('control');
        buttonControl.appendChild(submitButton);

        return [textarea, buttonControl];
    };

    const articleIdBasis = generateArticleIDBasis();
    const articleDiv = buildArticle(articleIdBasis.articleID, "Upload document", buildUploadFormElements(textareaId));
    const articleContainer = getElementById('article-container');
    articleContainer.prepend(articleDiv);

    getElementById(textareaId).focus();
};


const addUploadNewMockUsingBasicEIDASattributesFormArticleToContainer = () => {
    const buildFormElements = () => {

        const familyNameElement = createInputElement('family name', '', 'text');
        const givenNameElement = createInputElement('given name', '', 'text');
        const birthdateElement = createInputElement('birth date (YYYY-MM-DD)', '', 'text');
        const vctSelectWithinDivElement = createSelectElement([
            {value: 'urn:eudi:ehic:1', label: 'urn:eudi:ehic:1'},
            {value: '"urn:eudi:pda1:', label: '"urn:eudi:pda1:'},
            {value: 'urn:eu.europa.ec.eudi:pid:1"', label: 'urn:eudi:pid:1"'},
            {value: 'urn:eudi:elm:1', label: 'urn:eudi:elm:1'},
            {value: 'urn:eudi:diploma:1', label: 'urn:eudi:diploma:1'},
            {value: 'urn:eudi:micro_credential:1', label: 'urn:eudi:diploma:1'},
        ]);

        const vctDiv = vctSelectWithinDivElement[0];
        const vctSelect = vctSelectWithinDivElement[1];

        const createButton = document.createElement('button');
        createButton.id = generateUUID();
        createButton.classList.add('button', 'is-link');
        createButton.textContent = 'Upload business decision';
        createButton.onclick = () => {
            createButton.disabled = true;

            const requestBody = {
                family_name: familyNameElement.value,
                given_name: givenNameElement.value,
                birth_date: birthdateElement.value,
                vct: vctSelect.value,
            };

            disableElements([familyNameElement, givenNameElement, birthdateElement, vctSelect,]);

            postAndDisplayInArticleContainerFor("/secure/mockas/mock/next", requestBody, "Uploaded business decision");
        };

        return [familyNameElement, givenNameElement, birthdateElement, vctDiv, document.createElement('br'), createButton];
    };

    const articleIdBasis = generateArticleIDBasis();
    const articleDiv = buildArticle(articleIdBasis.articleID, "Upload new business decision", buildFormElements());
    const articleContainer = document.getElementById('article-container');
    articleContainer.prepend(articleDiv);

    document.getElementById(articleIdBasis.articleID).querySelector('input').focus();
};

const addViewVPFlowDebugInfoFormArticleToContainer = () => {
    const buildFormElements = () => {
        const sessionIDInput = createInputElement('session id');

        const divResultContainer = document.createElement("div");
        divResultContainer.id = generateUUID();

        const viewButton = document.createElement('button');
        viewButton.id = generateUUID();
        viewButton.classList.add('button', 'is-link');
        viewButton.textContent = 'View';
        viewButton.onclick = () => {
            divResultContainer.innerHTML = '';

            fetchData(new URL("/verifier/debug/vp-flow", baseUrl), {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json; charset=utf-8',
                },
                body: JSON.stringify({session_id: sessionIDInput.value}),
            }).then(data => {
                console.log(data);
                divResultContainer.appendChild(document.createElement("br"));
                divResultContainer.appendChild(document.createElement("br"));
                let debugData
                if (data && typeof data === 'object') {
                    debugData = JSON.stringify(data, null, 2);
                } else if (data === null) {
                    debugData = 'No debug data to display';
                } else {
                    debugData = String(data);
                }

                preElement = document.createElement("pre");
                preElement.innerText = debugData;
                const scrollXDiv = document.createElement("div");
                scrollXDiv.style.overflowX = 'auto';
                scrollXDiv.appendChild(preElement);
                divResultContainer.appendChild(scrollXDiv);
            }).catch(err => {
                console.debug("Unexpected error:", err);
                displayErrorTag("Failed to fetch vp-flow debug info: ", divResultContainer, err);
            });
        };
        triggerButtonOnEnter([sessionIDInput], viewButton);
        return [sessionIDInput, viewButton, divResultContainer];
    };

    const articleIdBasis = generateArticleIDBasis();
    const articleDiv = buildArticle(articleIdBasis.articleID, "View vp-flow debug info", buildFormElements());
    const articleContainer = document.getElementById('article-container');
    articleContainer.prepend(articleDiv);

    document.getElementById(articleIdBasis.articleID).querySelector('input').focus();

};

const createInputElement = (placeholder, value = '', type = 'text', disabled = false, title = '') => {
    const input = document.createElement('input');
    input.id = generateUUID();
    input.classList.add('input');
    input.type = type;
    input.placeholder = placeholder;
    input.value = value;
    input.disabled = disabled;
    input.title = title;
    return input;
};

const createInputElementAdvanced = ({
                                        placeholder,
                                        value = '',
                                        type = 'text',
                                        disabled = false,
                                        title = ''
                                    }) => {
    const input = document.createElement('input');
    input.id = generateUUID();
    input.classList.add('input');
    input.type = type;
    input.placeholder = placeholder;
    input.value = value;
    input.disabled = disabled;
    input.title = title; //tooltip
    return input;
};

function createCheckboxElement(labelText, disabled = false) {
    const label = document.createElement("label");
    label.classList.add("checkbox", "is-medium");
    label.id = generateUUID();

    const input = document.createElement("input");
    input.type = "checkbox";
    input.id = generateUUID();
    input.disabled = disabled;

    const textNode = document.createTextNode(labelText);

    label.appendChild(input);
    label.appendChild(textNode);

    return {label, input};
}

const createSelectElement = (options = [], disabled = false) => {
    const div = document.createElement('div');
    div.classList.add('select');

    const select = document.createElement('select');
    select.id = generateUUID();
    select.disabled = disabled;

    options.forEach(({value, label}) => {
        const option = document.createElement('option');
        option.value = value;
        option.textContent = label;
        select.appendChild(option);
    });

    div.appendChild(select);

    return [div, select];
};

const disableElements = (elements) => {
    elements.forEach(el => el.disabled = true);
};

const addViewDocumentFormArticleToContainer = () => {
    const buildFormElements = () => {

        const documentIDElement = createInputElement('document id');
        const scopeElement = createInputElement('scope');
        const authenticSourceElement = createInputElement('authentic source');

        const viewButton = document.createElement('button');
        viewButton.id = generateUUID();
        viewButton.classList.add('button', 'is-link');
        viewButton.textContent = 'View';
        viewButton.onclick = () => {
            viewButton.disabled = true;

            const requestBody = {
                document_id: documentIDElement.value,
                authentic_source: authenticSourceElement.value,
                scope: scopeElement.value,
            };

            disableElements([documentIDElement, scopeElement, authenticSourceElement]);

            postAndDisplayInArticleContainerFor("/secure/apigw/document", requestBody, "Document");
        };

        return [documentIDElement, scopeElement, authenticSourceElement, viewButton];
    };

    const articleIdBasis = generateArticleIDBasis();
    const articleDiv = buildArticle(articleIdBasis.articleID, "View document", buildFormElements());
    const articleContainer = document.getElementById('article-container');
    articleContainer.prepend(articleDiv);

    document.getElementById(articleIdBasis.articleID).querySelector('input').focus();
};


function buildDocumentsTableWithoutContent() {
    const table = document.createElement('table');
    table.className = 'table is-bordered is-striped is-narrow is-hoverable is-fullwidth';

    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');

    const headers = [
        {title: 'Action', abbr: null},
        {title: 'Document ID', abbr: null},
        {title: 'Scope', abbr: null},
        {title: 'Authentic source', abbr: null},
        {title: 'Identity Mapping IDs', abbr: null},
        {title: 'Credential offer url', abbr: null}
    ];

    headers.forEach(header => {
        const th = document.createElement('th');

        if (header.abbr) {
            const abbr = document.createElement('abbr');
            abbr.title = header.abbr;
            abbr.textContent = header.title;
            th.appendChild(abbr);
        } else {
            th.textContent = header.title;
        }

        headerRow.appendChild(th);
    });

    thead.appendChild(headerRow);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    table.appendChild(tbody);

    const scrollXDiv = document.createElement("div");
    scrollXDiv.style.overflowX = 'auto';
    scrollXDiv.appendChild(table);

    return {tableDiv: scrollXDiv, table: table, tbody: tbody};
}

function buildAndDisplayModal(title) {
    const modalId = generateUUID();
    const closeIconId = generateUUID();
    const closeButtonId = generateUUID();
    const modalBodyDivId = generateUUID();
    const footerId = generateUUID();

    const modal = document.createElement('div');
    modal.id = modalId;
    modal.className = 'modal is-active';
    modal.innerHTML = `
    <div class="modal-background"></div>
      <div class="modal-card" style="width: 90%; max-width: 1200px;">
      <header class="modal-card-head">
        <p class="modal-card-title">${title}</p>
        <button id="${closeIconId}" class="delete" aria-label="close"></button>
      </header>
      <section class="modal-card-body">
        <div id="${modalBodyDivId}"></div>
      </section>
      <footer id="${footerId}" class="modal-card-foot">
        <button id="${closeButtonId}" class="button is-success">Close</button>
      </footer>
    </div>
  `;

    document.body.appendChild(modal);

    const closeIcon = document.getElementById(closeIconId);
    const closeButton = document.getElementById(closeButtonId);

    closeIcon.addEventListener('click', () => closeModalAndRemoveFromDOM(modalId));
    closeButton.addEventListener('click', () => closeModalAndRemoveFromDOM(modalId));

    const modalBody = modal.querySelector('.modal-card-body');
    const modalBodyDiv = document.getElementById(modalBodyDivId);

    return {
        modal: modal,
        modalBody: modalBody,
        modalBodyDiv: modalBodyDiv,
        footer: document.getElementById(footerId),
    };
}

function copyContentWithinDivToClipboard(divId, jsonParseAndStringify = false) {
    const contentDiv = document.getElementById(divId);

    if (contentDiv) {
        let content = contentDiv.textContent || contentDiv.innerText;
        if (jsonParseAndStringify) {
            content = JSON.stringify(JSON.parse(content));
        }

        if (navigator.clipboard && navigator.clipboard.writeText) {
            // Modern Clipboard API (requires https)
            navigator.clipboard.writeText(content)
                .catch(err => {
                    console.error('Failed to copy content: ', err);
                    alert('Failed to copy content');
                });
        } else {
            // Fallback for older browsers (or http)
            const textArea = document.createElement('textarea');
            textArea.value = content;
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
            } catch (err) {
                console.error('Fallback: Unable to copy', err);
                alert('Failed to copy content');
            }
            document.body.removeChild(textArea);
        }
    } else {
        alert('No content to copy!');
    }
}

function closeModalAndRemoveFromDOM(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('is-active'); // Hide modal
        setTimeout(() => {
            modal.remove(); // Remove modal from DOM
        }, 300); // Wait until Bulma animations are done
    }
}

function displayErrorTag(errorText, parentElement, err = "") {
    const danger = document.createElement("span");
    danger.classList.add("tag", "is-danger", "is-medium");
    danger.innerText = errorText + err;
    parentElement.appendChild(danger);
}

function displayWarningTag(warningText, parentElement) {
    const warning = document.createElement("span");
    warning.classList.add("tag", "is-warning", "is-medium");
    warning.innerText = warningText;
    parentElement.appendChild(warning);
}

function displayInfoTag(infoText, parentElement) {
    const warning = document.createElement("span");
    warning.classList.add("tag", "is-info", "is-medium");
    warning.innerText = infoText;
    parentElement.appendChild(warning);
}

function displayCompleteDocumentInModal(rowData) {
    const modalParts = buildAndDisplayModal("Complete document as json");
    const modalBodyDiv = modalParts.modalBodyDiv;

    fetchData(new URL("/secure/apigw/document/search", baseUrl), {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json; charset=utf-8',
        },
        body: JSON.stringify({
            document_id: rowData.documentId,
            authentic_source: rowData.authenticSource,
            scope: rowData.scope,
            limit: parseInt(1, 10),
            fields: [],
        }),
    }).then(data => {
        if (Array.isArray(data.documents) && data.documents.length === 0) {
            displayErrorTag("No document found", modalBodyDiv);
            return;
        }

        modalBodyDiv.innerText = JSON.stringify(data.documents[0], null, 2);

        const copyButton = document.createElement("button");
        copyButton.id = generateUUID();
        copyButton.classList.add("button");
        copyButton.textContent = "Copy json";
        copyButton.addEventListener('click', () => copyContentWithinDivToClipboard(modalParts.modalBodyDiv.id, true));
        modalParts.footer.appendChild(copyButton);
    }).catch(err => {
        console.error("Unexpected error:", err);
        displayErrorTag("Failed to search for documents: ", modalBodyDiv, err);
    });
}

function buildButton({
                         id = generateUUID(),
                         text,
                         title = "",
                         classList = ["button", "is-link"],
                         onClick
                     }) {
    const button = document.createElement("button");
    button.id = id;
    button.textContent = text;
    button.title = title;

    classList.forEach(cls => button.classList.add(cls));

    if (typeof onClick === "function") {
        button.addEventListener("click", onClick);
    }
    return button;
}

function displayQRInModal(rowData) {
    const modalParts = buildAndDisplayModal("QR-code");
    const modalBodyDiv = modalParts.modalBodyDiv;

    fetchData(new URL("/secure/apigw/document/search", baseUrl), {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json; charset=utf-8',
        },
        body: JSON.stringify({
            document_id: rowData.documentId,
            authentic_source: rowData.authenticSource,
            scope: rowData.scope,
            limit: parseInt(1, 10),
            fields: ["qr"],
        }),
    }).then(data => {
        if (Array.isArray(data.documents) && data.documents.length === 0) {
            displayErrorTag("No document found", modalBodyDiv);
            //TODO(mk): check/error handling if no qr or base64_image exist
            return;
        }

        const credentialOfferUrl = data.documents[0].qr.credential_offer_url;

        const img = document.createElement("img");
        img.src = `data:image/png;base64,${data.documents[0].qr.qr_base64}`;

        const a = document.createElement("a");
        a.href = credentialOfferUrl;
        a.target = "_blank";
        a.title = credentialOfferUrl;
        a.appendChild(img);
        modalBodyDiv.appendChild(a);

        const toReplace = "openid-credential-offer://?";
        const dc4euWalletURL = safeReplace(credentialOfferUrl, toReplace, "https://dc4eu.wwwallet.org/cb?")
        modalParts.footer.appendChild(buildButton(
            {
                text: "DC4EU wallet",
                title: dc4euWalletURL,
                onClick: () => window.open(dc4euWalletURL, "_blank"),
            }
        ));

        const demoDC4EUWalletURL = safeReplace(credentialOfferUrl, toReplace, "https://demo.wwwallet.org/cb?");
        modalParts.footer.appendChild(buildButton(
            {
                text: "Demo DC4EU wallet",
                title: demoDC4EUWalletURL,
                onClick: () => window.open(demoDC4EUWalletURL, "_blank"),
            }
        ));

        const devSUNETWalletURL = safeReplace(credentialOfferUrl, toReplace, "https://dev.wallet.sunet.se/cb?");
        modalParts.footer.appendChild(buildButton(
            {
                text: "Dev SUNET wallet",
                title: devSUNETWalletURL,
                onClick: () => window.open(devSUNETWalletURL, "_blank"),
            }
        ));

        const funkeWalletURL = safeReplace(credentialOfferUrl, toReplace, "https://funke.wwwallet.org/cb?");
        modalParts.footer.appendChild(buildButton(
            {
                text: "Funke wallet",
                title: funkeWalletURL,
                onClick: () => window.open(funkeWalletURL, "_blank"),
            }
        ));

        //modalBodyDiv.innerText = JSON.stringify(data, null, 2);
    }).catch(err => {
        console.error("Unexpected error:", err);
        displayErrorTag("Failed to display QR-code: ", modalBodyDiv, err);
    });
}

function safeReplace(input, toReplace, replacement) {
    if (typeof input !== "string") return "";
    if (typeof toReplace !== "string" || toReplace === "") return input;
    if (!input.includes(toReplace)) return input;
    return input.replace(toReplace, replacement);
}

function displayDeleteDocumentInModal(rowData) {
    const modalParts = buildAndDisplayModal("Document deleted");
    const modalBodyDiv = modalParts.modalBodyDiv;

    fetchData(new URL("/secure/apigw/document", baseUrl), {
        method: 'DELETE',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json; charset=utf-8',
        },
        body: JSON.stringify({
            authentic_source: rowData.authenticSource,
            scope: rowData.scope,
            document_id: rowData.documentId,
        }),
    }).then(data => {
        displayInfoTag("Document deleted! A new search documents is required to refresh the result table in the browser", modalBodyDiv);
        //modalBodyDiv.innerText = JSON.stringify(data, null, 2);
    }).catch(err => {
        console.error("Unexpected error:", err);
        displayErrorTag("Failed to delete document: ", modalBodyDiv, err);
    });
}

function buildDocumentTableRow(doc) {
    const row = document.createElement('tr');

    //------select start-------------------
    const tdActions = document.createElement('td');
    const divSelect = document.createElement('div');
    divSelect.className = 'select'; // is-small';

    const select = document.createElement('select');
    select.id = generateUUID();

    const optionDefault = document.createElement('option');
    optionDefault.value = '';
    optionDefault.textContent = 'select...';
    select.appendChild(optionDefault);

    const optionViewDocument = document.createElement('option');
    optionViewDocument.value = 'VIEW_COMPLETE_DOCUMENT';
    optionViewDocument.textContent = 'View complete document';
    select.appendChild(optionViewDocument);

    const optionViewQR = document.createElement('option');
    optionViewQR.value = 'VIEW_QR';
    optionViewQR.textContent = 'View QR';
    select.appendChild(optionViewQR);

    select.appendChild(document.createElement('hr'));

    const optionDeleteDocument = document.createElement('option');
    optionDeleteDocument.value = 'DELETE_DOCUMENT';
    optionDeleteDocument.textContent = 'Delete document';
    select.appendChild(optionDeleteDocument);

    divSelect.appendChild(select);
    tdActions.appendChild(divSelect);
    row.appendChild(tdActions);
    //------select end-------------------

    const tdDocumentId = document.createElement('td');
    const documentId = doc.meta?.document_id || "";
    tdDocumentId.textContent = documentId;
    row.appendChild(tdDocumentId);

    const tdScope = document.createElement('td');
    const scope = doc.meta?.scope || "";
    tdScope.textContent = scope;
    row.appendChild(tdScope);

    const tdAuthenticSource = document.createElement('td');
    const authenticSource = doc.meta?.authentic_source || "";
    tdAuthenticSource.textContent = authenticSource;
    row.appendChild(tdAuthenticSource);

    const tdIdentityMappingIds = document.createElement('td');
    const ids = (doc.identity_mapping_ids || []).map(id => String(id));
    tdIdentityMappingIds.innerHTML = ids.join("<br>");
    row.appendChild(tdIdentityMappingIds);

    const tdQRCredentialOfferUrl = document.createElement('td');
    const credentialOfferUrl = doc.qr?.credential_offer_url || "";
    tdQRCredentialOfferUrl.textContent = credentialOfferUrl;
    row.appendChild(tdQRCredentialOfferUrl);

    const rowData = {
        documentId: documentId,
        authenticSource: authenticSource,
        scope: scope,
    };

    select.addEventListener('change', function () {
        const selectedValue = this.value;
        switch (selectedValue) {
            case 'VIEW_COMPLETE_DOCUMENT':
                displayCompleteDocumentInModal(rowData);
                break;
            case 'VIEW_QR':
                displayQRInModal(rowData);
                break;
            case 'DELETE_DOCUMENT':
                displayDeleteDocumentInModal(rowData);
                break;
            default:
                break;
        }
        this.value = '';
    });

    return row;
}

function displayDocumentsTable(data, divResultContainer) {
    divResultContainer.appendChild(document.createElement("br"));
    divResultContainer.appendChild(document.createElement("br"));

    if (data.documents == null || (Array.isArray(data.documents) && data.documents.length === 0)) {
        displayInfoTag("No matching documents found", divResultContainer);
        return;
    } else if (data.has_more_results) {
        displayWarningTag("There are more search results available. Narrow down your search criteria to view them all.", divResultContainer);
    }

    const exportToCsvButton = document.createElement("button");
    exportToCsvButton.id = generateUUID();
    exportToCsvButton.classList.add('button', 'is-link');
    exportToCsvButton.textContent = "Export result to csv file";
    exportToCsvButton.disabled = false;
    divResultContainer.appendChild(exportToCsvButton);

    const tableBasis = buildDocumentsTableWithoutContent();
    exportToCsvButton.addEventListener('click', () => exportTableToCSV(tableBasis.table));
    divResultContainer.appendChild(tableBasis.tableDiv);
    data.documents.forEach(doc => {
        tableBasis.tbody.appendChild(buildDocumentTableRow(doc));
    });
}

function exportTableToCSV(table) {
    const rows = table.querySelectorAll('tr');
    let csvContent = "";

    rows.forEach(row => {
        const cells = row.querySelectorAll('th, td');
        const rowContent = Array.from(cells)
            .map(cell => `"${cell.innerText}"`) // Wrap cell values in quotes to handle commas
            .join(","); // Join cell values with a comma
        csvContent += rowContent + "\n";
    });


    const blob = new Blob([csvContent], {type: 'text/csv'});
    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');
    a.href = url;
    a.download = 'search_result.csv';
    document.body.appendChild(a);
    a.click();

    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function triggerButtonOnEnter(inputs, buttonOrHandler) {
    const handler = typeof buttonOrHandler === 'function'
        ? buttonOrHandler
        : () => buttonOrHandler.click();

    inputs.forEach(input => {
        input.addEventListener('keydown', function (event) {
            if (event.key === 'Enter') {
                event.preventDefault();
                handler();
            }
        });
    });
}

const addSearchDocumentsFormArticleToContainer = () => {
    const buildFormElements = () => {
        const documentIDInput = createInputElement('Document id (optional)');
        const authenticSourceInput = createInputElement('Authentic source (optional)');
        const scopeInput = createInputElement('Scope (optional, e.g. ehic, pda1, pid_1_8)');
        const collectIdInput = createInputElement('Collect ID (optional)');
        const authenticSourcePersonIdInput = createInputElement('Authentic source person id (optional)');
        const {
            label: checkboxShowCompleteDocsAsRawJsonLabel,
            input: checkboxShowCompleteDocsAsRawJson
        } = createCheckboxElement("Show complete documents as raw json");
        const limitInput = createInputElement('Max number of results (optional, default is 50, max is 500)', '50');

        const divResultContainer = document.createElement("div");
        divResultContainer.id = generateUUID();

        const searchButton = document.createElement('button');
        searchButton.id = generateUUID();
        searchButton.classList.add('button', 'is-link');
        searchButton.textContent = 'Search';
        searchButton.onclick = () => {
            const path = "/secure/apigw/document/search";
            divResultContainer.innerHTML = '';
            if (checkboxShowCompleteDocsAsRawJson.checked) {
                searchButton.disabled = true;
            }

            const requestBody = {
                document_id: documentIDInput.value,
                authentic_source: authenticSourceInput.value,
                scope: scopeInput.value,
                collect_id: collectIdInput.value,

                authentic_source_person_id: authenticSourcePersonIdInput.value,

                limit: parseInt(limitInput.value, 10),

                fields: ["meta.document_id", "meta.authentic_source", "meta.scope", "identity_mapping_ids", "qr.credential_offer_url"],
            };

            if (checkboxShowCompleteDocsAsRawJson.checked) {
                requestBody.fields = []; // request all fields
                disableElements([
                    documentIDInput,
                    authenticSourceInput,
                    scopeInput,
                    collectIdInput,
                    authenticSourcePersonIdInput,
                    checkboxShowCompleteDocsAsRawJson,
                    limitInput
                ]);
                //TODO(mk): display raw json in same div as the result table
                postAndDisplayInArticleContainerFor(path, requestBody, "Documents");
            } else {
                fetchData(new URL(path, baseUrl), {
                    method: 'POST',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json; charset=utf-8',
                    },
                    body: JSON.stringify(requestBody),
                }).then(data => {
                    displayDocumentsTable(data, divResultContainer);
                }).catch(err => {
                    console.debug("Unexpected error:", err);
                    displayErrorTag("Failed to search for documents: ", divResultContainer, err);
                });
            }
        };

        let brElement = document.createElement('br');

        triggerButtonOnEnter([documentIDInput, authenticSourceInput, scopeInput, collectIdInput, authenticSourcePersonIdInput, checkboxShowCompleteDocsAsRawJson, limitInput], searchButton);

        return [
            documentIDInput,
            authenticSourceInput,
            scopeInput,
            collectIdInput,
            authenticSourcePersonIdInput,
            searchButton,
            brElement,
            checkboxShowCompleteDocsAsRawJsonLabel,
            limitInput,
            divResultContainer];
    };

    const articleIdBasis = generateArticleIDBasis();
    const articleDiv = buildArticle(articleIdBasis.articleID, "Search documents", buildFormElements());
    const articleContainer = document.getElementById('article-container');
    articleContainer.prepend(articleDiv);

    document.getElementById(articleIdBasis.articleID).querySelector('input').focus();
};

async function fetchData(url, options) {
    try {
        const response = await fetch(url, options);

        if (!response.ok) {
            let errorDetails = `HTTP error! status: ${response.status}, url: ${url}`;

            try {
                const errorData = await response.json();
                errorDetails += `, details: ${JSON.stringify(errorData)}`;
            } catch (jsonError) {
                errorDetails += `, details: (Unable to parse JSON)`;
            }

            if (response.status === 401) {
                throw new Error("Unauthorized/session expired");
            }

            throw new Error(errorDetails);
        }

        return await response.json();
    } catch (error) {
        if (error instanceof TypeError) {
            throw new Error(`Network error or server did not respond. URL: ${url}, Details: ${error.message}`);
        }

        throw new Error(`Error: ${error.message}`);
    }
}

const addViewNotificationFormArticleToContainer = () => {
    const buildFormElements = () => {

        const documentIDElement = createInputElement('document id');
        const scopeElement = createInputElement('scope', 'ehic');
        const authenticSourceElement = createInputElement('authentic source', 'SUNET');

        const viewButton = document.createElement('button');
        viewButton.id = generateUUID();
        viewButton.classList.add('button', 'is-link');
        viewButton.textContent = 'View';
        viewButton.onclick = () => {
            viewButton.disabled = true;

            const requestBody = {
                document_id: documentIDElement.value,
                authentic_source: authenticSourceElement.value,
                scope: scopeElement.value,
            };

            disableElements([documentIDElement, scopeElement, authenticSourceElement]);

            postAndDisplayInArticleContainerFor("/secure/apigw/notification", requestBody, "Notification");
        };

        return [documentIDElement, scopeElement, authenticSourceElement, viewButton];
    };

    const articleIdBasis = generateArticleIDBasis();
    const articleDiv = buildArticle(articleIdBasis.articleID, "View notification", buildFormElements());
    const articleContainer = document.getElementById('article-container');
    articleContainer.prepend(articleDiv);

    document.getElementById(articleIdBasis.articleID).querySelector('input').focus();
};

const addLoginArticleToContainer = () => {
    const buildLoginElements = () => {
        const usernameField = document.createElement('div');
        usernameField.classList.add('field');

        const usernameLabel = document.createElement('label');
        usernameLabel.classList.add('label');
        usernameLabel.textContent = 'Username';

        const usernameControl = document.createElement('div');
        usernameControl.classList.add('control');

        const usernameInput = document.createElement('input');
        usernameInput.id = 'username-input';
        usernameInput.classList.add('input');
        usernameInput.type = 'text';
        usernameInput.placeholder = 'Username';
        usernameInput.addEventListener('keypress', function (event) {
            if (event.key === 'Enter') {
                document.getElementById('do-login-btn').click();
            }
        });

        usernameControl.appendChild(usernameInput);
        usernameField.appendChild(usernameLabel);
        usernameField.appendChild(usernameControl);

        const passwordField = document.createElement('div');
        passwordField.classList.add('field');

        const passwordLabel = document.createElement('label');
        passwordLabel.classList.add('label');
        passwordLabel.textContent = 'Password';

        const passwordControl = document.createElement('div');
        passwordControl.classList.add('control');

        const passwordInput = document.createElement('input');
        passwordInput.id = 'password-input';
        passwordInput.classList.add('input');
        passwordInput.type = 'password';
        passwordInput.placeholder = 'Password';
        passwordInput.addEventListener('keypress', function (event) {
            if (event.key === 'Enter') {
                document.getElementById('do-login-btn').click();
            }
        });

        passwordControl.appendChild(passwordInput);
        passwordField.appendChild(passwordLabel);
        passwordField.appendChild(passwordControl);

        const submitButton = document.createElement('button');
        submitButton.id = 'do-login-btn';
        submitButton.classList.add('button', 'is-link');
        submitButton.textContent = 'Submit';
        submitButton.onclick = () => doLogin();

        const buttonControl = document.createElement('div');
        buttonControl.classList.add('control');
        buttonControl.appendChild(submitButton);

        return [usernameField, passwordField, buttonControl];
    };

    clearContainer("login-container"); //To always only have 0..1 login articles displayed
    const articleIdBasis = generateArticleIDBasis();
    const articleDiv = buildArticle(articleIdBasis.articleID, "Login", buildLoginElements());
    const loginContainer = getElementById('login-container');
    loginContainer.prepend(articleDiv);

    getElementById("username-input").focus();
};

async function doLogout() {
    const url = new URL("/secure/logout", baseUrl);
    //console.debug("doLogout for url: " + url);

    const headers = {
        'Accept': 'application/json', 'Content-Type': 'application/json'
    };

    const request = new Request(url, {
        method: "DELETE", headers: headers
    });

    //TODO(mk): add error handling
    await fetch(request);
    hideSecureMenyItems();
    clearAllContentContainers();
}

function toggleExpandCollapseArticle(articleId) {
    const article = document.getElementById(articleId);
    const content = article.querySelector('.message-body');
    if (content.style.display === 'none') {
        content.style.display = 'block';  // Ändra detta värde beroende på din stil
    } else {
        content.style.display = 'none';
    }
}

window.addEventListener('load', function () {
    if (isLoggedIn()) {
        displaySecureMenyItems();
    } else {
        hideSecureMenyItems();
    }
});