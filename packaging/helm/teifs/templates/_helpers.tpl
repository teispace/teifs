{{- define "teifs.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "teifs.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else if contains (include "teifs.name" .) .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "teifs.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "teifs.selectorLabels" -}}
app.kubernetes.io/name: {{ include "teifs.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "teifs.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "teifs.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "teifs.secretName" -}}
{{- default (include "teifs.fullname" .) .Values.auth.existingSecret }}
{{- end }}

{{- define "teifs.scheme" -}}
{{- if .Values.tls.existingSecret }}HTTPS{{ else }}HTTP{{ end }}
{{- end }}
