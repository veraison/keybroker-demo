package arm_cca

default allow := false

allow if {
    input.eat_profile == "tag:github.com,2023:veraison/ear"

    # platform part
    prec := input.submods.CCA_SSD_PLATFORM
    prec["ear.status"] == "affirming"

    # realm part
    rrec := input.submods.CCA_REALM
    rrec["ear.status"] == "warning"

    rtv := rrec["ear.trustworthiness-vector"]
    rtv["instance-identity"] == 2

    # check RIM value against known-good-values
    rclaims := rrec["ear.veraison.annotated-evidence"]
    rim := rclaims["cca-realm-initial-measurement"]
    rim in data["reference-values"]
}