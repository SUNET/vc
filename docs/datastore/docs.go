// Package docs Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {},
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/document": {
            "post": {
                "description": "Get document endpoint",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "dc4eu"
                ],
                "summary": "GetDocument",
                "operationId": "get-document",
                "parameters": [
                    {
                        "description": " ",
                        "name": "req",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/apiv1.GetDocumentRequest"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Success",
                        "schema": {
                            "$ref": "#/definitions/apiv1.GetDocumentReply"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/helpers.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/document/collection_code": {
            "post": {
                "description": "Get document by collection code endpoint",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "dc4eu"
                ],
                "summary": "GetDocumentByCollectionCode",
                "operationId": "get-document-collection-code",
                "parameters": [
                    {
                        "description": " ",
                        "name": "req",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/model.MetaData"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Success",
                        "schema": {
                            "$ref": "#/definitions/apiv1.GetDocumentReply"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/helpers.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/id_mapping": {
            "post": {
                "description": "ID mapping endpoint",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "dc4eu"
                ],
                "summary": "IDMapping",
                "operationId": "id-mapping",
                "parameters": [
                    {
                        "description": " ",
                        "name": "req",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/model.MetaData"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Success",
                        "schema": {
                            "$ref": "#/definitions/apiv1.IDMappingReply"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/helpers.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/metadata": {
            "post": {
                "description": "List metadata endpoint",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "dc4eu"
                ],
                "summary": "ListMetadata",
                "operationId": "list-metadata",
                "parameters": [
                    {
                        "description": " ",
                        "name": "req",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/apiv1.ListMetadataRequest"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Success",
                        "schema": {
                            "$ref": "#/definitions/apiv1.ListMetadataReply"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/helpers.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/portal": {
            "post": {
                "description": "Get document by collection code endpoint",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "dc4eu"
                ],
                "summary": "ListMetadata",
                "operationId": "portal",
                "parameters": [
                    {
                        "description": " ",
                        "name": "req",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/apiv1.PortalRequest"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Success",
                        "schema": {
                            "$ref": "#/definitions/apiv1.PortalReply"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/helpers.ErrorResponse"
                        }
                    }
                }
            }
        },
        "/upload": {
            "post": {
                "description": "Upload endpoint",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "dc4eu"
                ],
                "summary": "Upload",
                "operationId": "generic-upload",
                "parameters": [
                    {
                        "description": " ",
                        "name": "req",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/model.Upload"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Success",
                        "schema": {
                            "$ref": "#/definitions/apiv1.UploadReply"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "$ref": "#/definitions/helpers.ErrorResponse"
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "apiv1.GetDocumentReply": {
            "type": "object",
            "properties": {
                "data": {
                    "$ref": "#/definitions/model.Upload"
                }
            }
        },
        "apiv1.GetDocumentRequest": {
            "type": "object",
            "properties": {
                "authentic_source": {
                    "type": "string"
                },
                "document_id": {
                    "type": "string"
                },
                "document_type": {
                    "type": "string"
                }
            }
        },
        "apiv1.IDMappingReply": {
            "type": "object",
            "properties": {
                "data": {
                    "type": "object",
                    "properties": {
                        "authentic_source_person_id": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "apiv1.ListMetadataReply": {
            "type": "object",
            "properties": {
                "data": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/model.MetaData"
                    }
                }
            }
        },
        "apiv1.ListMetadataRequest": {
            "type": "object",
            "properties": {
                "authentic_source": {
                    "type": "string"
                },
                "authentic_source_person_id": {
                    "type": "string"
                }
            }
        },
        "apiv1.PortalReply": {
            "type": "object",
            "properties": {
                "data": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/model.MetaData"
                    }
                }
            }
        },
        "apiv1.PortalRequest": {
            "type": "object",
            "properties": {
                "authentic_source": {
                    "type": "string"
                },
                "authentic_source_person_id": {
                    "type": "string"
                }
            }
        },
        "apiv1.UploadReply": {
            "type": "object",
            "properties": {
                "data": {
                    "type": "object",
                    "properties": {
                        "status": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "helpers.Error": {
            "type": "object",
            "properties": {
                "details": {},
                "title": {
                    "type": "string"
                }
            }
        },
        "helpers.ErrorResponse": {
            "type": "object",
            "properties": {
                "error": {
                    "$ref": "#/definitions/helpers.Error"
                }
            }
        },
        "model.MetaData": {
            "type": "object",
            "required": [
                "authentic_source",
                "authentic_source_person_id",
                "collect_id",
                "date_of_birth",
                "document_id",
                "document_type",
                "first_name",
                "last_name",
                "revocation_id",
                "uid"
            ],
            "properties": {
                "authentic_source": {
                    "type": "string"
                },
                "authentic_source_person_id": {
                    "type": "string"
                },
                "collect_id": {
                    "type": "string"
                },
                "date_of_birth": {
                    "type": "string"
                },
                "document_id": {
                    "type": "string"
                },
                "document_type": {
                    "type": "string",
                    "enum": [
                        "PDA1",
                        "EHIC"
                    ]
                },
                "first_name": {
                    "type": "string"
                },
                "last_name": {
                    "type": "string"
                },
                "qr": {
                    "$ref": "#/definitions/model.QR"
                },
                "revocation_id": {
                    "type": "string"
                },
                "uid": {
                    "type": "string"
                }
            }
        },
        "model.QR": {
            "type": "object",
            "required": [
                "base64_image"
            ],
            "properties": {
                "base64_image": {
                    "type": "string"
                }
            }
        },
        "model.Upload": {
            "type": "object",
            "required": [
                "document_data",
                "meta"
            ],
            "properties": {
                "document_data": {},
                "meta": {
                    "$ref": "#/definitions/model.MetaData"
                }
            }
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "0.1.0",
	Host:             "",
	BasePath:         "/datastore/api/v1",
	Schemes:          []string{},
	Title:            "Datastore API",
	Description:      "",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}