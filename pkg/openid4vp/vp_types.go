package openid4vp

type InputDescriptor struct {
	ID          string                         `json:"id"`
	Name        string                         `json:"name,omitempty"`
	Purpose     string                         `json:"purpose,omitempty"`
	Format      map[string]map[string][]string `json:"format,omitempty"`
	Group       []string                       `json:"group,omitempty"`
	Constraints Constraints                    `json:"constraints"`
}

type Format struct {
	Alg []string `json:"alg"`
}

type Constraints struct {
	LimitDisclosure string  `json:"limit_disclosure,omitempty"`
	Fields          []Field `json:"fields,omitempty"`
}

type Field struct {
	Name   string   `json:"name,omitempty"`
	Path   []string `json:"path"`
	Filter *Filter  `json:"filter,omitempty"`
}

type Filter struct {
	Type  string   `json:"type,omitempty"`
	Enum  []string `json:"enum,omitempty"`
	Const string   `json:"const,omitempty"`
}

type SubmissionRequirement struct {
	Name  string `json:"name,omitempty"`
	Rule  string `json:"rule"`
	Count int    `json:"count,omitempty"`
	From  string `json:"from"`
}

type Descriptor struct {
	ID         string      `json:"id" validate:"required"`
	Path       string      `json:"path" validate:"required"`
	PathNested *Descriptor `json:"path_nested,omitempty"`
	Format     string      `json:"format" validate:"required,oneof=jwt jwt_vc jwt_vp ldp ldp_vc ldp_vp mso_mdoc ac_vc ac_vp sd_jwt"`
}

type PresentationSubmission struct {
	ID            string       `json:"id" validate:"required"`
	DefinitionID  string       `json:"definition_id" validate:"required"`
	DescriptorMap []Descriptor `json:"descriptor_map" validate:"required,dive,required"`
}
