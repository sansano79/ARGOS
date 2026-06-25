import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const TEAM_UI_PATH = new URL("./TeamUi.jsx", import.meta.url);

const loadDialogHelpers = async () => {
  const source = await readFile(TEAM_UI_PATH, "utf8");
  const boundary = source.indexOf("export const PageHeader");
  const moduleSource = source
    .slice(0, boundary)
    .replace('import { useEffect, useId, useRef } from "react";\n\n', "");
  return import(`data:text/javascript;charset=utf-8,${encodeURIComponent(moduleSource)}`);
};

const createWindowStub = () => {
  const listeners = new Map();
  return {
    addEventListener(type, handler) {
      listeners.set(type, handler);
    },
    removeEventListener(type, handler) {
      if (listeners.get(type) === handler) listeners.delete(type);
    },
    dispatch(type, event) {
      listeners.get(type)?.(event);
    },
  };
};

const createFocusable = (name, documentTarget) => ({
  name,
  focus() {
    documentTarget.activeElement = this;
  },
});

const createPanelStub = ({
  autoFocusTarget = null,
  inputTarget = null,
  selectTarget = null,
  textareaTarget = null,
  buttonTarget = null,
} = {}) => ({
  querySelector(selector) {
    if (selector === "[autofocus]") return autoFocusTarget;
    if (selector === "input:not([disabled]):not([type='hidden'])") return inputTarget;
    if (selector === "select:not([disabled])") return selectTarget;
    if (selector === "textarea:not([disabled])") return textareaTarget;
    if (selector === "button:not([disabled])") return buttonTarget;
    return null;
  },
});

test("team modal name field keeps focus while typing IT España and later fields also keep focus", async () => {
  const { setupDialogFrameFocusLifecycle } = await loadDialogHelpers();
  const documentTarget = { activeElement: null };
  const windowTarget = createWindowStub();
  const opener = createFocusable("open-create-team", documentTarget);
  const nameInput = createFocusable("name", documentTarget);
  const codeInput = createFocusable("code", documentTarget);
  const descriptionInput = createFocusable("description", documentTarget);
  const closeButton = createFocusable("close", documentTarget);

  documentTarget.activeElement = opener;

  const panel = createPanelStub({
    autoFocusTarget: nameInput,
    inputTarget: nameInput,
    textareaTarget: descriptionInput,
    buttonTarget: closeButton,
  });

  const restoreFocusRef = { current: null };
  const onCloseRef = { current: () => {} };
  const cleanup = setupDialogFrameFocusLifecycle({
    panel,
    restoreFocusRef,
    onCloseRef,
    documentTarget,
    windowTarget,
  });

  assert.equal(documentTarget.activeElement, nameInput);

  let typedName = "";
  for (const character of "IT España") {
    typedName += character;
    onCloseRef.current = () => typedName;
    assert.equal(documentTarget.activeElement, nameInput);
  }
  assert.equal(typedName, "IT España");

  codeInput.focus();
  for (const character of "it-es") {
    onCloseRef.current = () => character;
    assert.equal(documentTarget.activeElement, codeInput);
  }

  descriptionInput.focus();
  for (const character of "Equipo corporativo") {
    onCloseRef.current = () => character;
    assert.equal(documentTarget.activeElement, descriptionInput);
  }

  cleanup();
});

test("Escape uses the latest onClose callback and cleanup restores focus to opener", async () => {
  const { setupDialogFrameFocusLifecycle } = await loadDialogHelpers();
  const documentTarget = { activeElement: null };
  const windowTarget = createWindowStub();
  const opener = createFocusable("open-member-form", documentTarget);
  const nameInput = createFocusable("name", documentTarget);
  const closeButton = createFocusable("close", documentTarget);

  documentTarget.activeElement = opener;

  const panel = createPanelStub({
    autoFocusTarget: nameInput,
    inputTarget: nameInput,
    buttonTarget: closeButton,
  });

  const restoreFocusRef = { current: null };
  let closedBy = "none";
  const onCloseRef = { current: () => { closedBy = "initial"; } };
  const cleanup = setupDialogFrameFocusLifecycle({
    panel,
    restoreFocusRef,
    onCloseRef,
    documentTarget,
    windowTarget,
  });

  onCloseRef.current = () => { closedBy = "latest"; };
  windowTarget.dispatch("keydown", { key: "Escape" });
  assert.equal(closedBy, "latest");

  cleanup();
  assert.equal(documentTarget.activeElement, opener);
});

test("DialogFrame focus priority respects autofocus and falls back to the first form control for all subscriber team forms", async () => {
  const { findPreferredDialogFocusTarget } = await loadDialogHelpers();
  const documentTarget = { activeElement: null };
  const closeButton = createFocusable("close", documentTarget);
  const teamNameInput = createFocusable("team-name", documentTarget);
  const memberUserSelect = createFocusable("member-user", documentTarget);
  const recipientEmailInput = createFocusable("recipient-email", documentTarget);
  const subscriptionVendorInput = createFocusable("subscription-vendor", documentTarget);
  const systemNameInput = createFocusable("system-name", documentTarget);

  assert.equal(
    findPreferredDialogFocusTarget(createPanelStub({
      autoFocusTarget: teamNameInput,
      inputTarget: teamNameInput,
      buttonTarget: closeButton,
    })),
    teamNameInput,
  );

  assert.equal(
    findPreferredDialogFocusTarget(createPanelStub({
      selectTarget: memberUserSelect,
      buttonTarget: closeButton,
    })),
    memberUserSelect,
  );

  assert.equal(
    findPreferredDialogFocusTarget(createPanelStub({
      autoFocusTarget: recipientEmailInput,
      inputTarget: recipientEmailInput,
      buttonTarget: closeButton,
    })),
    recipientEmailInput,
  );

  assert.equal(
    findPreferredDialogFocusTarget(createPanelStub({
      autoFocusTarget: subscriptionVendorInput,
      inputTarget: subscriptionVendorInput,
      buttonTarget: closeButton,
    })),
    subscriptionVendorInput,
  );

  assert.equal(
    findPreferredDialogFocusTarget(createPanelStub({
      autoFocusTarget: systemNameInput,
      inputTarget: systemNameInput,
      buttonTarget: closeButton,
    })),
    systemNameInput,
  );
});
