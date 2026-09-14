{{- define "vexviper.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{- define "vexviper.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vexviper.labels" -}}
app.kubernetes.io/name: {{ include "vexviper.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "vexviper.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vexviper.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "vexviper.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{- define "vexviper.secretName" -}}
{{- default (include "vexviper.fullname" .) .Values.bomhort.existingSecret -}}
{{- end -}}

{{/* Shared container env */}}
{{- define "vexviper.env" -}}
- name: VEXVIPER_BOMHORT_URL
  value: {{ .Values.bomhort.url | quote }}
- name: VEXVIPER_VEX_UPLOAD
  value: {{ .Values.upload | quote }}
- name: BOMHORT_API_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "vexviper.secretName" . }}
      key: api-key
      optional: true
- name: OPENAI_API_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "vexviper.secretName" . }}
      key: openai-api-key
      optional: true
{{- with .Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/* Shared pod spec pieces */}}
{{- define "vexviper.volumes" -}}
- name: config
  configMap:
    name: {{ include "vexviper.fullname" . }}
- name: work
{{- if .Values.persistence.enabled }}
  persistentVolumeClaim:
    claimName: {{ default (include "vexviper.fullname" .) .Values.persistence.existingClaim }}
{{- else }}
  emptyDir: {}
{{- end }}
{{- end -}}

{{- define "vexviper.volumeMounts" -}}
- name: config
  mountPath: /etc/vexviper
  readOnly: true
- name: work
  mountPath: /work
{{- end -}}
