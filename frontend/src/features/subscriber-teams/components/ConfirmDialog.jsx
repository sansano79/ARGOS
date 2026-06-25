import { Button, DialogFrame, InlineMessage } from "./TeamUi.jsx";

export default function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = "Confirmar",
  cancelLabel = "Cancelar",
  danger = false,
  loading = false,
  onConfirm,
  onClose,
}) {
  if (!open) return null;

  return (
    <DialogFrame
      title={title}
      onClose={loading ? () => {} : onClose}
      footer={(
        <>
          <Button onClick={onClose} disabled={loading}>{cancelLabel}</Button>
          <Button danger={danger} primary={!danger} onClick={onConfirm} disabled={loading}>
            {loading ? "Procesando..." : confirmLabel}
          </Button>
        </>
      )}
    >
      <InlineMessage type={danger ? "error" : "info"}>
        {description}
      </InlineMessage>
    </DialogFrame>
  );
}

