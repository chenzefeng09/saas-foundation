{{/* =============================================================================
     Service template helpers
     ============================================================================= */}}

{{- define "service.fullname" -}}
{{- printf "foundation-%s" .Values.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "service.labels" -}}
app.kubernetes.io/name: {{ .Values.name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: foundation
app.kubernetes.io/part-of: saas-foundation
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
foundation.example.com/profile: {{ .Values.global.profile | default "small" }}
{{- end -}}

{{- define "service.selectorLabels" -}}
app.kubernetes.io/name: {{ .Values.name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "service.image" -}}
{{- $registry := .Values.global.imageRegistry | default "" -}}
{{- $repo := .Values.image.repository -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- if $registry -}}
{{ $registry }}/{{ $repo }}:{{ $tag }}
{{- else -}}
{{ $repo }}:{{ $tag }}
{{- end -}}
{{- end -}}

{{/* Common env vars injected into every service */}}
{{- define "service.commonEnv" -}}
- name: FOUNDATION_SERVICE_NAME
  value: {{ .Values.name | quote }}
- name: FOUNDATION_PROFILE
  value: {{ .Values.global.profile | default "small" | quote }}
- name: FOUNDATION_COMPLIANCE_MODES
  value: {{ .Values.global.complianceModes | default (list "pipl") | join "," | quote }}
- name: FOUNDATION_DATA_RESIDENCY
  value: {{ .Values.global.dataResidency | default "cn-only" | quote }}
- name: TZ
  value: {{ .Values.global.timezone | default "Asia/Shanghai" | quote }}
# Observability
- name: OTEL_SERVICE_NAME
  value: {{ printf "foundation-%s" .Values.name | quote }}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: {{ .Values.global.otelCollector.endpoint | quote }}
- name: OTEL_RESOURCE_ATTRIBUTES
  value: {{ printf "service.namespace=foundation,deployment.environment=%s" .Values.global.profile | quote }}
# Database (all services share the same gateway)
- name: FOUNDATION_DB_HOST
  value: {{ .Values.global.database.host | quote }}
- name: FOUNDATION_DB_PORT
  value: {{ .Values.global.database.port | quote }}
- name: FOUNDATION_DB_NAME
  value: {{ .Values.global.database.name | quote }}
- name: FOUNDATION_DB_USER
  valueFrom:
    secretKeyRef:
      name: {{ .Values.global.database.existingSecret }}
      key: app_user
- name: FOUNDATION_DB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.global.database.existingSecret }}
      key: app_user_password
# Redis
- name: FOUNDATION_REDIS_HOST
  value: {{ .Values.global.redis.host | quote }}
- name: FOUNDATION_REDIS_PORT
  value: {{ .Values.global.redis.port | quote }}
- name: FOUNDATION_REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .Values.global.redis.existingSecret }}
      key: password
# Keycloak
- name: FOUNDATION_KEYCLOAK_URL
  value: {{ .Values.global.keycloak.url | quote }}
- name: FOUNDATION_KEYCLOAK_REALM
  value: {{ .Values.global.keycloak.realm | quote }}
# Vault
- name: FOUNDATION_VAULT_ADDR
  value: {{ .Values.global.vault.addr | quote }}
- name: FOUNDATION_VAULT_ROLE
  value: {{ .Values.global.vault.role | quote }}
{{- end -}}
