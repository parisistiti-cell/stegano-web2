/* Direction visuelle : atelier de cryptographie éditoriale — composition asymétrique, ivoire d’archive, encre bleu-noir, jade propriétaire, annotations monospace. */
import { ChangeEvent, DragEvent, KeyboardEvent, useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, ArrowDown, Check, CheckCircle2, Copy, Dices, Download, Eye, EyeOff, FileAudio, FileImage, FileVideo, ImagePlus, LockKeyhole, Moon, ScanLine, Search, Sun, Trash2, Upload } from "lucide-react";
import AdminPanel from "./Admin";

const MAGIC = new TextEncoder().encode("STEGANO1");
const HEADER_BYTES = MAGIC.length + 4;
const HERO_IMAGE = `${import.meta.env.BASE_URL}hero.png`;

// Images de démonstration servies depuis client/public. Un lien du type
// "?demo=<nom-du-fichier>" précharge l'image correspondante et bascule sur
// le mode LIRE, pour que le visiteur n'ait plus qu'à saisir la clé. Le nom
// de fichier suffit : aucune modification de code n'est nécessaire pour
// ajouter une nouvelle image, voir la page /admin pour générer le lien.
// DEMO_ALIASES permet de garder des liens plus courts pour certaines images.
const DEMO_ALIASES: Record<string, string> = {
  "ford-focus": "ford focus.png",
};

type Mode = "encode" | "decode";
const MODES: readonly Mode[] = ["encode", "decode"];
type Probe = "idle" | "checking" | "found" | "none";
type Status = { tone: "idle" | "success" | "error"; text: string };

// Type de contenu que l'on peut dissimuler dans l'image porteuse. Le
// premier octet du paquet chiffré indique le type, ce qui permet au
// décodage de reconstituer le bon fichier (aperçu + téléchargement).
type PayloadKind = "text" | "image" | "audio" | "video";
const PAYLOAD_KIND_CODES: Record<PayloadKind, number> = { text: 0, image: 1, audio: 2, video: 3 };
const PAYLOAD_KIND_FROM_CODE: Record<number, PayloadKind> = { 0: "text", 1: "image", 2: "audio", 3: "video" };
const PAYLOAD_KIND_LABELS: Record<PayloadKind, string> = { text: "un texte", image: "une image", audio: "un fichier audio (MP3)", video: "une vidéo (MP4)" };
const PAYLOAD_KIND_ACCEPT: Record<PayloadKind, string> = { text: "", image: "image/*", audio: "audio/mpeg,audio/mp3,.mp3", video: "video/mp4,.mp4" };
const PAYLOAD_KIND_EXT: Record<PayloadKind, string> = { text: "txt", image: "png", audio: "mp3", video: "mp4" };

const PAYLOAD_KINDS: readonly PayloadKind[] = ["text", "image", "audio", "video"];

type DecodedFile = { url: string; filename: string; kind: Exclude<PayloadKind, "text">; size: number; mime: string };

function guessMimeFromFilename(filename: string, kind: PayloadKind) {
  const lower = filename.toLowerCase();
  if (kind === "image") {
    if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
    if (lower.endsWith(".bmp")) return "image/bmp";
    if (lower.endsWith(".webp")) return "image/webp";
    return "image/png";
  }
  if (kind === "audio") return "audio/mpeg";
  if (kind === "video") return "video/mp4";
  return "text/plain";
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} Mo`;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const FERNET_VERSION = 0x80;
const FERNET_SALT_BYTES = 16;
const FERNET_ITERATIONS = 200_000;
const FERNET_MARKER = encoder.encode("###FIN###");

function concatBytes(...parts: Uint8Array[]) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}

function base64UrlEncode(bytes: Uint8Array) {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 1) binary += String.fromCharCode(bytes[index]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(value: string) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

async function deriveFernetKeys(password: string, salt: Uint8Array) {
  const baseKey = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const derived = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: FERNET_ITERATIONS, hash: "SHA-256" }, baseKey, 256));
  const signingKey = await crypto.subtle.importKey("raw", derived.slice(0, 16), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  const encryptionKey = await crypto.subtle.importKey("raw", derived.slice(16), { name: "AES-CBC" }, false, ["encrypt", "decrypt"]);
  return { signingKey, encryptionKey };
}

async function encryptLikeFernet(messageBytes: Uint8Array, password: string) {
  const salt = crypto.getRandomValues(new Uint8Array(FERNET_SALT_BYTES));
  const { signingKey, encryptionKey } = await deriveFernetKeys(password, salt);
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const timestamp = new Uint8Array(8);
  new DataView(timestamp.buffer).setBigUint64(0, BigInt(Math.floor(Date.now() / 1000)));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, encryptionKey, messageBytes));
  const unsignedToken = concatBytes(new Uint8Array([FERNET_VERSION]), timestamp, iv, ciphertext);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", signingKey, unsignedToken));
  return base64UrlEncode(concatBytes(salt, unsignedToken, signature));
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

async function decryptLikeFernet(packet: string, password: string): Promise<Uint8Array> {
  const decoded = base64UrlDecode(packet);
  if (decoded.length < FERNET_SALT_BYTES + 1 + 8 + 16 + 16 + 32) throw new Error("Paquet chiffré incomplet.");
  const salt = decoded.slice(0, FERNET_SALT_BYTES);
  const token = decoded.slice(FERNET_SALT_BYTES);
  const unsignedToken = token.slice(0, -32);
  const signature = token.slice(-32);
  if (unsignedToken[0] !== FERNET_VERSION) throw new Error("Version Fernet non reconnue.");
  const { signingKey, encryptionKey } = await deriveFernetKeys(password, salt);
  const expected = new Uint8Array(await crypto.subtle.sign("HMAC", signingKey, unsignedToken));
  if (!constantTimeEqual(signature, expected)) throw new Error("Signature invalide.");
  const iv = unsignedToken.slice(9, 25);
  const ciphertext = unsignedToken.slice(25);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, encryptionKey, ciphertext);
  return new Uint8Array(plaintext);
}

// Le contenu à dissimuler est précédé d'un petit en-tête (type + nom de
// fichier) avant chiffrement, afin que le décodage puisse reconstituer le
// bon type de fichier (image / audio / vidéo) et proposer le bon nom.
function buildHeaderedPayload(kind: PayloadKind, filename: string, content: Uint8Array) {
  const nameBytes = encoder.encode(filename).slice(0, 255);
  const header = new Uint8Array(2 + nameBytes.length);
  header[0] = PAYLOAD_KIND_CODES[kind];
  header[1] = nameBytes.length;
  header.set(nameBytes, 2);
  return concatBytes(header, content);
}

function parseHeaderedPayload(bytes: Uint8Array) {
  if (bytes.length < 2) throw new Error("Paquet déchiffré invalide.");
  const kind = PAYLOAD_KIND_FROM_CODE[bytes[0]] ?? "text";
  const nameLength = bytes[1];
  const filename = decoder.decode(bytes.slice(2, 2 + nameLength));
  const content = bytes.slice(2 + nameLength);
  return { kind, filename, content };
}

function readImage(file: File): Promise<{ image: HTMLImageElement; url: string }> {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const image = new Image();
    image.onload = () => resolve({ image, url });
    image.onerror = () => { URL.revokeObjectURL(url); reject(new Error("Cette image ne peut pas être lue par le navigateur.")); };
    image.src = url;
  });
}

// Lit les bits de poids faible (RGB) octet par octet et s'arrête dès que le
// marqueur de fin est trouvé : pas de tableau d'un nombre par bit, donc pas
// de plantage mémoire sur les grandes photos.
function readHiddenPacket(data: Uint8ClampedArray): Uint8Array | null {
  const marker = FERNET_MARKER;
  const m = marker.length;
  const out = new Uint8Array(Math.floor(((data.length / 4) * 3) / 8));
  let byte = 0;
  let bitCount = 0;
  let n = 0;
  for (let i = 0; i < data.length; i += 4) {
    for (let channel = 0; channel < 3; channel += 1) {
      byte = (byte << 1) | (data[i + channel] & 1);
      bitCount += 1;
      if (bitCount === 8) {
        out[n++] = byte;
        byte = 0;
        bitCount = 0;
        if (n >= m && out[n - 1] === marker[m - 1]) {
          let match = true;
          for (let k = 0; k < m; k += 1) { if (out[n - m + k] !== marker[k]) { match = false; break; } }
          if (match) return out.subarray(0, n - m);
        }
      }
    }
  }
  return null;
}

// Taille réelle du paquet inscrit : en-tête + chiffrement AES-CBC (bourrage
// PKCS7) + signature, le tout en base64 sans remplissage, plus le marqueur.
function estimatePacketBytes(contentLength: number, nameLength: number) {
  const plain = 2 + nameLength + contentLength;
  const padded = (Math.floor(plain / 16) + 1) * 16;
  const tokenBytes = FERNET_SALT_BYTES + 1 + 8 + 16 + padded + 32;
  return Math.ceil((tokenBytes * 4) / 3) + FERNET_MARKER.length;
}

// Place réellement utilisable pour un contenu, selon la capacité brute de l'image.
function maxContentBytes(rawCapacity: number, nameLength: number) {
  const tokenMax = Math.floor(((rawCapacity - FERNET_MARKER.length) * 3) / 4);
  const paddedMax = Math.floor((tokenMax - (FERNET_SALT_BYTES + 1 + 8 + 16 + 32)) / 16) * 16;
  return Math.max(0, paddedMax - 1 - 2 - nameLength);
}

const tick = () => new Promise<void>((resolve) => window.setTimeout(resolve, 30));

// Phrase de passe lisible : 4 groupes de 4 caractères sans ambiguïté (≈ 80 bits).
function generatePassphrase() {
  const alphabet = "abcdefghjkmnpqrstuvwxyz23456789";
  const random = crypto.getRandomValues(new Uint8Array(16));
  const chars = Array.from(random, (value) => alphabet[value % alphabet.length]);
  return [0, 4, 8, 12].map((start) => chars.slice(start, start + 4).join("")).join("-");
}

function arrowNav<T extends string>(event: KeyboardEvent<HTMLElement>, values: readonly T[], current: T, set: (value: T) => void) {
  if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
  event.preventDefault();
  const index = values.indexOf(current);
  set(values[(index + (event.key === "ArrowRight" ? 1 : values.length - 1)) % values.length]);
  const group = event.currentTarget;
  window.requestAnimationFrame(() => group.querySelector<HTMLElement>('[tabindex="0"]')?.focus());
}

function StepTitle({ n, title, done, hint }: { n: number; title: string; done: boolean; hint?: string }) {
  return (
    <div className="step-title">
      <span className={`step-num ${done ? "done" : ""}`} aria-hidden="true">{done ? <Check size={14} /> : n}</span>
      <h3>{title}</h3>
      {hint && <span className="step-hint">{hint}</span>}
    </div>
  );
}

function canvasFromImage(image: HTMLImageElement) {
  const canvas = document.createElement("canvas");
  canvas.width = image.naturalWidth;
  canvas.height = image.naturalHeight;
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) throw new Error("Le contexte graphique n’est pas disponible.");
  context.drawImage(image, 0, 0);
  return { canvas, context, imageData: context.getImageData(0, 0, canvas.width, canvas.height) };
}

export default function Home() {
  const [showAdmin] = useState(() => typeof window !== "undefined" && new URLSearchParams(window.location.search).has("admin"));
  const [mode, setMode] = useState<Mode>("encode");
  const [file, setFile] = useState<File | null>(null);
  const [image, setImage] = useState<HTMLImageElement | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [result, setResult] = useState<{ url: string; size: number } | null>(null);
  const [verifyImage, setVerifyImage] = useState<HTMLImageElement | null>(null);
  const [message, setMessage] = useState("");
  const [payloadKind, setPayloadKind] = useState<PayloadKind>("text");
  const [payloadFile, setPayloadFile] = useState<File | null>(null);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [decodedMessage, setDecodedMessage] = useState("");
  const [decodedFile, setDecodedFile] = useState<DecodedFile | null>(null);
  const [textFilename, setTextFilename] = useState("message_decode");
  const [isBusy, setIsBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressLabel, setProgressLabel] = useState("");
  const [probe, setProbe] = useState<Probe>("idle");
  const [dragTarget, setDragTarget] = useState<"carrier" | "payload" | null>(null);
  const [isDark, setIsDark] = useState(() => {
    if (typeof window === "undefined") return false;
    const saved = localStorage.getItem("stegano-theme");
    if (saved) return saved === "dark";
    // Sur smartphone, le mode sombre est activé par défaut tant que
    // l'utilisateur n'a jamais choisi explicitement un thème.
    return window.matchMedia("(max-width: 860px)").matches;
  });
  const [toast, setToast] = useState("");
  const [status, setStatus] = useState<Status>({ tone: "idle", text: "" });
  const inputRef = useRef<HTMLInputElement>(null);
  const payloadInputRef = useRef<HTMLInputElement>(null);
  const packetCache = useRef<{ image: HTMLImageElement; packet: string | null } | null>(null);

  // Image réellement analysée : en mode LIRE, l'image qu'on vient de chiffrer
  // (bouton « Tester le décodage ») prend la place de l'image porteuse d'origine.
  const activeImage = mode === "decode" ? (verifyImage ?? image) : image;
  const activeName = mode === "decode" && verifyImage ? "stegano-message.png" : file?.name ?? "";
  const shownUrl = mode === "decode" ? (verifyImage && result ? result.url : previewUrl) : (result?.url ?? previewUrl);

  useEffect(() => {
    document.documentElement.classList.toggle("dark", isDark);
    localStorage.setItem("stegano-theme", isDark ? "dark" : "light");
  }, [isDark]);

  useEffect(() => {
    const demoKey = new URLSearchParams(window.location.search).get("demo");
    if (!demoKey) return;
    const demoFile = DEMO_ALIASES[demoKey] ?? demoKey;
    (async () => {
      try {
        const response = await fetch(`${import.meta.env.BASE_URL}${encodeURIComponent(demoFile)}`);
        if (!response.ok) throw new Error("Image de démonstration introuvable.");
        const blob = await response.blob();
        const demo = new File([blob], demoFile, { type: blob.type || "image/png" });
        setMode("decode");
        await handleFileRef.current(demo);
        setStatus({ tone: "idle", text: "Image de démonstration chargée. Entrez la clé pour révéler le message caché." });
      } catch (error) {
        setStatus({ tone: "error", text: error instanceof Error ? error.message : "Impossible de charger l’image de démonstration." });
      }
    })();
    // Exécuté une seule fois au chargement de la page.
  }, []);

  // Collage d'une image depuis le presse-papiers (Ctrl+V / Cmd+V).
  useEffect(() => {
    const onPaste = (event: ClipboardEvent) => {
      const pasted = Array.from(event.clipboardData?.files ?? []).find((item) => item.type.startsWith("image/"));
      if (!pasted) return;
      event.preventDefault();
      void handleFileRef.current(pasted);
    };
    window.addEventListener("paste", onPaste);
    return () => window.removeEventListener("paste", onPaste);
  }, []);

  // En mode LIRE, on vérifie tout de suite (sans la clé) si l'image contient des données cachées.
  useEffect(() => {
    if (mode !== "decode" || !activeImage) { setProbe("idle"); return; }
    setProbe("checking");
    const timer = window.setTimeout(() => {
      try { setProbe(getPacket(activeImage) ? "found" : "none"); } catch { setProbe("none"); }
    }, 40);
    return () => window.clearTimeout(timer);
  }, [mode, activeImage]);

  function getPacket(img: HTMLImageElement): string | null {
    const cached = packetCache.current;
    if (cached && cached.image === img) return cached.packet;
    const { imageData } = canvasFromImage(img);
    const bytes = readHiddenPacket(imageData.data);
    let packet: string | null = null;
    if (bytes && bytes.length > 0) {
      const text = decoder.decode(bytes);
      if (/^[A-Za-z0-9_-]+$/.test(text)) packet = text;
    }
    packetCache.current = { image: img, packet };
    return packet;
  }

  function showToast(text: string) {
    setToast(text);
    window.setTimeout(() => setToast(""), 2600);
  }

  // Capacité brute en octets, puis place réellement utilisable une fois le contenu chiffré.
  const rawCapacity = image ? Math.floor((image.naturalWidth * image.naturalHeight * 3) / 8) : 0;
  const contentBytes = payloadKind === "text" ? encoder.encode(message).length : payloadFile?.size ?? 0;
  const nameLength = payloadKind === "text" || !payloadFile ? 0 : encoder.encode(payloadFile.name).slice(0, 255).length;
  const usableBytes = useMemo(() => (image ? maxContentBytes(rawCapacity, nameLength) : 0), [image, rawCapacity, nameLength]);
  const neededBytes = estimatePacketBytes(contentBytes, nameLength);
  const fillRatio = rawCapacity ? Math.min(1, neededBytes / rawCapacity) : 0;
  const tooBig = !!image && contentBytes > 0 && neededBytes > rawCapacity;

  // Raison pour laquelle le bouton principal est inactif (affichée juste dessous).
  const encodeBlocker: string | null = !image ? "Ajoutez d’abord une image porteuse (étape 1)."
    : payloadKind === "text" && !message.trim() ? "Écrivez le message à cacher (étape 2)."
    : payloadKind !== "text" && !payloadFile ? `Choisissez ${PAYLOAD_KIND_LABELS[payloadKind]} à dissimuler (étape 2).`
    : tooBig ? "Contenu trop volumineux pour cette image : choisissez une image plus grande ou un contenu plus léger."
    : !password ? "Choisissez une clé secrète (étape 3)."
    : password !== confirmPassword ? "Les deux clés ne sont pas identiques."
    : null;
  const decodeBlocker: string | null = !activeImage ? "Ajoutez d’abord une image à inspecter (étape 1)."
    : !password ? "Entrez la clé secrète (étape 2)."
    : null;

  const handleFileRef = useRef(handleFile);
  handleFileRef.current = handleFile;

  async function handleFile(nextFile?: File) {
    if (!nextFile) return;
    if (!nextFile.type.startsWith("image/")) {
      setStatus({ tone: "error", text: "Choisissez un fichier image PNG, JPG ou BMP." });
      return;
    }
    try {
      const loaded = await readImage(nextFile);
      if (previewUrl) URL.revokeObjectURL(previewUrl);
      if (decodedFile) URL.revokeObjectURL(decodedFile.url);
      if (result) URL.revokeObjectURL(result.url);
      setFile(nextFile);
      setImage(loaded.image);
      setPreviewUrl(loaded.url);
      setResult(null);
      setVerifyImage(null);
      setDecodedMessage("");
      setDecodedFile(null);
      setStatus({ tone: "success", text: "Image prête pour une opération locale." });
    } catch (error) {
      setStatus({ tone: "error", text: error instanceof Error ? error.message : "Impossible de lire cette image." });
    }
  }

  function clearImage() {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    if (decodedFile) URL.revokeObjectURL(decodedFile.url);
    if (result) URL.revokeObjectURL(result.url);
    setFile(null);
    setImage(null);
    setPreviewUrl(null);
    setResult(null);
    setVerifyImage(null);
    setDecodedMessage("");
    setDecodedFile(null);
    setProbe("idle");
    setStatus({ tone: "idle", text: "" });
    if (inputRef.current) inputRef.current.value = "";
  }

  function onFileChange(event: ChangeEvent<HTMLInputElement>) {
    void handleFile(event.target.files?.[0]);
    event.target.value = "";
  }
  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragTarget(null);
    void handleFile(event.dataTransfer.files?.[0]);
  }
  function onPayloadFileChange(event: ChangeEvent<HTMLInputElement>) {
    setPayloadFile(event.target.files?.[0] ?? null);
    event.target.value = "";
  }
  function onPayloadDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragTarget(null);
    const dropped = event.dataTransfer.files?.[0];
    if (dropped) setPayloadFile(dropped);
  }
  function dropZoneKey(event: KeyboardEvent<HTMLDivElement>, open: () => void) {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); open(); }
  }

  function changePayloadKind(kind: PayloadKind) {
    setPayloadKind(kind);
    setPayloadFile(null);
  }

  function makePassphrase() {
    const phrase = generatePassphrase();
    setPassword(phrase);
    setConfirmPassword(phrase);
    setShowPassword(true);
    showToast("Clé générée : notez-la, elle ne peut pas être retrouvée");
  }

  async function copyKey() {
    if (!password) return;
    try {
      await navigator.clipboard.writeText(password);
      showToast("Clé copiée dans le presse-papiers");
    } catch {
      setStatus({ tone: "error", text: "La copie a échoué. Vérifiez les permissions du navigateur." });
    }
  }

  async function encode() {
    if (encodeBlocker || !image) return setStatus({ tone: "error", text: encodeBlocker ?? "Ajoutez d’abord une image porteuse." });
    setIsBusy(true);
    setProgress(8);
    setProgressLabel("Préparation du contenu");
    try {
      await tick();
      const rawContent = payloadKind === "text" ? encoder.encode(message) : new Uint8Array(await payloadFile!.arrayBuffer());
      const filename = payloadKind === "text" ? "" : payloadFile!.name;
      const headeredPayload = buildHeaderedPayload(payloadKind, filename, rawContent);
      setProgress(24);
      setProgressLabel("Dérivation de la clé sécurisée");
      await tick();
      const encrypted = await encryptLikeFernet(headeredPayload, password);
      setProgress(58);
      setProgressLabel("Chiffrement du contenu");
      await tick();
      const payload = encoder.encode(encrypted) ;
      const packet = concatBytes(payload, FERNET_MARKER);
      const rawBits = image.naturalWidth * image.naturalHeight * 3;
      if (packet.length * 8 > rawBits) return setStatus({ tone: "error", text: `Contenu chiffré trop volumineux : ${formatBytes(packet.length)} pour ${formatBytes(Math.floor(rawBits / 8))} disponibles. Utilisez une image porteuse plus grande.` });
      setProgress(73);
      setProgressLabel("Inscription dans les pixels");
      await tick();
      const { canvas, context, imageData } = canvasFromImage(image);
      const totalBits = packet.length * 8;
      let bitIndex = 0;
      for (let i = 0; i < imageData.data.length && bitIndex < totalBits; i += 4) {
        for (let channel = 0; channel < 3 && bitIndex < totalBits; channel += 1) {
          const bit = (packet[bitIndex >> 3] >> (7 - (bitIndex & 7))) & 1;
          imageData.data[i + channel] = (imageData.data[i + channel] & 0xfe) | bit;
          bitIndex += 1;
        }
      }
      setProgress(91);
      setProgressLabel("Écriture de l’image PNG");
      await tick();
      context.putImageData(imageData, 0, 0);
      const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, "image/png"));
      if (!blob) throw new Error("L’export PNG a échoué.");
      if (result) URL.revokeObjectURL(result.url);
      setVerifyImage(null);
      setResult({ url: URL.createObjectURL(blob), size: blob.size });
      setProgress(100);
      setProgressLabel("Traitement terminé");
      setStatus({ tone: "success", text: payloadKind === "text" ? "Message chiffré et inscrit dans une copie PNG." : `${filename} chiffré et inscrit dans une copie PNG.` });
    } catch (error) {
      setStatus({ tone: "error", text: error instanceof Error ? error.message : "L’encodage a échoué." });
    } finally {
      setIsBusy(false);
      window.setTimeout(() => { setProgress(0); setProgressLabel(""); }, 500);
    }
  }

  async function decode() {
    if (decodeBlocker || !activeImage) return setStatus({ tone: "error", text: decodeBlocker ?? "Ajoutez d’abord une image à inspecter." });
    setIsBusy(true);
    setProgress(12);
    setProgressLabel("Lecture des pixels");
    try {
      await tick();
      const packet = getPacket(activeImage);
      if (!packet) throw new Error("Aucune donnée cachée détectée dans cette image.");
      setProgress(42);
      setProgressLabel("Vérification de la clé");
      await tick();
      const extractedBytes = await decryptLikeFernet(packet, password);
      setProgress(85);
      setProgressLabel("Reconstitution du contenu");
      await tick();
      const { kind, filename, content } = parseHeaderedPayload(extractedBytes);
      if (decodedFile) URL.revokeObjectURL(decodedFile.url);
      if (kind === "text") {
        const text = decoder.decode(content);
        setDecodedMessage(text);
        setDecodedFile(null);
        setStatus({ tone: "success", text: `Message déchiffré : ${formatBytes(content.length)}.` });
      } else {
        const mime = guessMimeFromFilename(filename, kind);
        const blob = new Blob([content], { type: mime });
        const url = URL.createObjectURL(blob);
        const safeFilename = filename || `fichier_decode.${PAYLOAD_KIND_EXT[kind]}`;
        setDecodedMessage("");
        setDecodedFile({ url, filename: safeFilename, kind, size: content.length, mime });
        setStatus({ tone: "success", text: `Fichier déchiffré : ${safeFilename} (${formatBytes(content.length)}).` });
      }
      setProgress(100);
      setProgressLabel("Traitement terminé");
    } catch (error) {
      setDecodedMessage("");
      setDecodedFile(null);
      setStatus({ tone: "error", text: error instanceof Error && error.message === "Signature invalide." ? "Clé incorrecte, ou image sans message chiffré par cet outil." : error instanceof Error ? error.message : "Le décodage a échoué." });
    } finally {
      setIsBusy(false);
      window.setTimeout(() => { setProgress(0); setProgressLabel(""); }, 500);
    }
  }

  async function copyDecodedText() {
    if (!decodedMessage) return setStatus({ tone: "error", text: "Décodez d’abord un message avant de le copier." });
    try {
      await navigator.clipboard.writeText(decodedMessage);
      setStatus({ tone: "success", text: "Le message décodé a été copié dans le presse-papiers." });
      showToast("Message copié dans le presse-papiers");
    } catch {
      setStatus({ tone: "error", text: "La copie a échoué. Vérifiez les permissions du navigateur." });
    }
  }

  function download() {
    if (!result) return;
    const anchor = document.createElement("a");
    anchor.href = result.url;
    anchor.download = "stegano-message.png";
    anchor.click();
  }

  // Recharge l'image qu'on vient de chiffrer en mode LIRE pour vérifier qu'elle se relit bien.
  function testDecode() {
    if (!result) return;
    const verify = new Image();
    verify.onload = () => {
      setVerifyImage(verify);
      setDecodedMessage("");
      setDecodedFile(null);
      setMode("decode");
      setStatus({ tone: "idle", text: "Image chiffrée chargée. Entrez la clé pour vérifier qu’elle se relit." });
      document.getElementById("outil")?.scrollIntoView({ behavior: "smooth", block: "start" });
    };
    verify.onerror = () => setStatus({ tone: "error", text: "Impossible de recharger l’image chiffrée." });
    verify.src = result.url;
  }

  function downloadDecodedFile() {
    if (!decodedFile) return;
    const anchor = document.createElement("a");
    anchor.href = decodedFile.url;
    anchor.download = decodedFile.filename;
    anchor.click();
    setStatus({ tone: "success", text: `Le fichier a été enregistré sous ${decodedFile.filename}.` });
  }

  function saveDecodedText() {
    if (!decodedMessage) return setStatus({ tone: "error", text: "Décodez d’abord un message avant de l’enregistrer." });
    const blob = new Blob([decodedMessage], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    const safeName = textFilename.trim().replace(/[^a-zA-Z0-9À-ÿ _-]/g, "_") || "message_decode";
    anchor.download = `${safeName.endsWith(".txt") ? safeName : `${safeName}.txt`}`;
    anchor.click();
    URL.revokeObjectURL(url);
    setStatus({ tone: "success", text: `Le message décodé a été enregistré dans ${safeName.endsWith(".txt") ? safeName : `${safeName}.txt`}.` });
  }

  if (showAdmin) return <AdminPanel />;

  const keyInput = (id: string, value: string, onChange: (value: string) => void, placeholder: string) => (
    <div className="key-field">
      <input id={id} type={showPassword ? "text" : "password"} value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} autoComplete="off" autoCapitalize="off" spellCheck={false} />
      <button type="button" className="key-toggle" onClick={() => setShowPassword((visible) => !visible)} aria-label={showPassword ? "Masquer la clé" : "Afficher la clé"}>{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button>
    </div>
  );

  const statusBlock = (
    <>
      {isBusy && <div className="progress-panel" role="status" aria-live="polite"><div className="progress-head"><span>{progressLabel}</span><strong>{progress}%</strong></div><div className="progress-track"><span style={{ width: `${progress}%` }} /></div></div>}
      {status.text && <div className={`status-message ${status.tone}`} aria-live="polite"><span className="status-pip" />{status.text}</div>}
    </>
  );

  return (
    <main className="site-shell">
      <header className="topbar">
        <a className="brand" href="#outil" aria-label="Stegano Web, aller à l’atelier">
          <span>Stegano <i>Web</i></span>
        </a>
        <div className="top-actions">
          <div className="top-meta"><span className="status-dot" /> TRAITEMENT LOCAL <span className="meta-divider" /> AUCUN COMPTE</div>
          <button className="theme-toggle" onClick={() => setIsDark((dark) => !dark)} aria-label={isDark ? "Activer le mode clair" : "Activer le mode sombre"}>{isDark ? <Sun size={16} /> : <Moon size={16} />}<span>{isDark ? "MODE CLAIR" : "MODE SOMBRE"}</span></button>
        </div>
      </header>

      <section className="hero" id="atelier">
        <div className="hero-copy">
          <h1>Un message.<br /><em>Une image.</em><br />Une clé.</h1>
          <p className="hero-lede">Dissimulez un texte, une image, un son ou une vidéo dans les pixels d’une image, directement dans votre navigateur. Vos fichiers restent sur votre appareil.</p>
          <ol className="hero-steps">
            <li><b>1</b> Choisissez une image</li>
            <li><b>2</b> Ajoutez votre contenu</li>
            <li><b>3</b> Protégez-le avec une clé</li>
          </ol>
          <a className="hero-cta" href="#outil">Commencer <ArrowDown size={16} /></a>
        </div>
        <div className="hero-art"><img src={HERO_IMAGE} alt="Composition éditoriale autour d’une image et d’une grille de pixels" /></div>
      </section>

      <section className="workbench" id="outil" aria-label="Atelier Stegano Web">
        <div className="workspace">
          <div className="workspace-head">
            <h2>Cacher ou révéler<br /><em>un secret.</em></h2>
            <div className="mode-switch" role="tablist" aria-label="Mode de travail" onKeyDown={(event) => arrowNav(event, MODES, mode, setMode)}>
              <button type="button" id="tab-encode" role="tab" aria-selected={mode === "encode"} aria-controls="panel-main" tabIndex={mode === "encode" ? 0 : -1} className={mode === "encode" ? "active" : ""} onClick={() => setMode("encode")}><LockKeyhole size={17} /> CACHER</button>
              <button type="button" id="tab-decode" role="tab" aria-selected={mode === "decode"} aria-controls="panel-main" tabIndex={mode === "decode" ? 0 : -1} className={mode === "decode" ? "active" : ""} onClick={() => setMode("decode")}><ScanLine size={17} /> RÉVÉLER</button>
            </div>
          </div>

          <div className="workspace-grid" id="panel-main" role="tabpanel" aria-labelledby={mode === "encode" ? "tab-encode" : "tab-decode"}>
            <div className="preview-column">
              <StepTitle n={1} title={mode === "encode" ? "Image porteuse" : "Image à inspecter"} done={!!activeImage} hint="PNG · JPG · BMP" />
              <div
                className={`drop-zone ${shownUrl ? "has-image" : ""} ${dragTarget === "carrier" ? "dragging" : ""}`}
                onDragOver={(event) => { event.preventDefault(); setDragTarget("carrier"); }}
                onDragLeave={() => setDragTarget(null)}
                onDrop={onDrop}
                onClick={() => inputRef.current?.click()}
                role="button"
                tabIndex={0}
                aria-label={shownUrl ? "Changer d’image" : "Choisir une image"}
                onKeyDown={(event) => dropZoneKey(event, () => inputRef.current?.click())}
              >
                {shownUrl ? <img src={shownUrl} alt="Aperçu de l’image sélectionnée" /> : <><FileImage size={34} strokeWidth={1.2} /><strong>Déposez une image ici</strong><span>cliquez pour parcourir, ou collez-la avec Ctrl+V</span></>}
                <input ref={inputRef} type="file" accept="image/png,image/jpeg,image/bmp" onChange={onFileChange} hidden />
              </div>
              {activeImage && <>
                <div className="image-facts">
                  <div><span>NOM</span><strong title={activeName}>{activeName || "—"}</strong></div>
                  <div><span>DIMENSIONS</span><strong>{activeImage.naturalWidth} × {activeImage.naturalHeight}</strong></div>
                  <div><span>CAPACITÉ</span><strong>≈ {formatBytes(maxContentBytes(Math.floor((activeImage.naturalWidth * activeImage.naturalHeight * 3) / 8), 0))}</strong></div>
                </div>
                <div className="image-actions">
                  <button type="button" className="secondary-action" onClick={() => inputRef.current?.click()}><ImagePlus size={15} /> Changer d’image</button>
                  <button type="button" className="secondary-action" onClick={clearImage}><Trash2 size={15} /> Retirer</button>
                </div>
              </>}
              {mode === "decode" && activeImage && (
                <div className={`probe probe-${probe}`} role="status" aria-live="polite">
                  {probe === "checking" && <><span className="loading-spinner dark" /> Analyse de l’image…</>}
                  {probe === "found" && <><CheckCircle2 size={17} /> Données cachées détectées : entrez la clé pour les lire.</>}
                  {probe === "none" && <><Search size={17} /> Aucune donnée cachée détectée dans cette image.</>}
                </div>
              )}
            </div>

            <div className="operation-column">
              {mode === "encode" ? <>
                <StepTitle n={2} title="Contenu à cacher" done={!encodeBlocker || (!!image && !tooBig && (payloadKind === "text" ? !!message.trim() : !!payloadFile))} />
                <fieldset className="payload-fieldset">
                  <legend className="field-label">TYPE DE CONTENU</legend>
                  <div className="payload-switch" role="radiogroup" aria-label="Type de contenu à cacher" onKeyDown={(event) => arrowNav(event, PAYLOAD_KINDS, payloadKind, changePayloadKind)}>
                    {PAYLOAD_KINDS.map((kind) => (
                      <button key={kind} type="button" role="radio" aria-checked={payloadKind === kind} tabIndex={payloadKind === kind ? 0 : -1} className={payloadKind === kind ? "active" : ""} onClick={() => changePayloadKind(kind)}>
                        {kind === "text" ? "TEXTE" : kind === "image" ? <><FileImage size={14} /> IMAGE</> : kind === "audio" ? <><FileAudio size={14} /> AUDIO MP3</> : <><FileVideo size={14} /> VIDÉO MP4</>}
                      </button>
                    ))}
                  </div>
                </fieldset>
                {payloadKind === "text" ? <>
                  <label className="field-label" htmlFor="secret-message">MESSAGE À DISSIMULER <span>{formatBytes(contentBytes)}</span></label>
                  <textarea id="secret-message" value={message} onChange={(event) => setMessage(event.target.value)} placeholder="Écrivez ici le message qui voyagera dans l’image…" rows={7} />
                </> : <>
                  <span className="field-label">{payloadKind === "image" ? "IMAGE" : payloadKind === "audio" ? "FICHIER MP3" : "FICHIER MP4"} À DISSIMULER <span>{payloadFile ? formatBytes(payloadFile.size) : "—"}</span></span>
                  <div
                    className={`drop-zone payload-drop ${payloadFile ? "has-image" : ""} ${dragTarget === "payload" ? "dragging" : ""}`}
                    onDragOver={(event) => { event.preventDefault(); setDragTarget("payload"); }}
                    onDragLeave={() => setDragTarget(null)}
                    onDrop={onPayloadDrop}
                    onClick={() => payloadInputRef.current?.click()}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(event) => dropZoneKey(event, () => payloadInputRef.current?.click())}
                  >
                    {payloadFile ? <>{payloadKind === "image" ? <FileImage size={28} strokeWidth={1.2} /> : payloadKind === "audio" ? <FileAudio size={28} strokeWidth={1.2} /> : <FileVideo size={28} strokeWidth={1.2} />}<strong>{payloadFile.name}</strong><span>{formatBytes(payloadFile.size)} · cliquez pour changer de fichier</span></> : <><Upload size={28} strokeWidth={1.2} /><strong>Déposez {PAYLOAD_KIND_LABELS[payloadKind]} ici</strong><span>ou cliquez pour parcourir vos fichiers</span></>}
                    <input ref={payloadInputRef} type="file" accept={PAYLOAD_KIND_ACCEPT[payloadKind]} onChange={onPayloadFileChange} hidden />
                  </div>
                </>}
                <div className="meter-block">
                  <div className="meter" role="img" aria-label={image ? `Place utilisée : ${Math.round(fillRatio * 100)} %` : "Place disponible inconnue"}><span className={tooBig ? "over" : ""} style={{ width: `${Math.max(fillRatio * 100, contentBytes > 0 ? 2 : 0)}%` }} /></div>
                  <p className={`meter-caption ${tooBig ? "over" : ""}`}>{image ? `${formatBytes(contentBytes)} à cacher · maximum utile ≈ ${formatBytes(usableBytes)} pour cette image (chiffrement compris)` : "Ajoutez une image pour connaître la place disponible."}</p>
                </div>

                <StepTitle n={3} title="Clé secrète" done={!!password && password === confirmPassword} hint="PBKDF2 · FERNET" />
                <label className="field-label" htmlFor="encode-key">CLÉ <span>sans elle, rien ne sera récupérable</span></label>
                {keyInput("encode-key", password, setPassword, "Entrez la clé de chiffrement")}
                <label className="field-label key-label" htmlFor="encode-key-confirm">CONFIRMER LA CLÉ</label>
                {keyInput("encode-key-confirm", confirmPassword, setConfirmPassword, "Saisissez-la une seconde fois")}
                {confirmPassword && password !== confirmPassword && <p className="key-mismatch" role="alert">Les deux clés ne sont pas identiques.</p>}
                <div className="key-tools">
                  <button type="button" className="secondary-action" onClick={makePassphrase}><Dices size={15} /> Générer une clé forte</button>
                  <button type="button" className="secondary-action" onClick={() => void copyKey()} disabled={!password}><Copy size={15} /> Copier la clé</button>
                </div>

                <button className="primary-action full-width" onClick={() => void encode()} disabled={isBusy || !!encodeBlocker} aria-describedby="action-reason">
                  {isBusy ? <><span className="loading-spinner" /> CHIFFREMENT EN COURS…</> : <><LockKeyhole size={17} /> CHIFFRER ET INSCRIRE</>}
                </button>
                <p className="action-reason" id="action-reason">{isBusy ? "" : encodeBlocker ?? "Tout est prêt : l’image d’origine n’est jamais modifiée, vous obtenez une nouvelle copie PNG."}</p>
                {statusBlock}

                {result && (
                  <div className="result-card">
                    <div className="result-head"><CheckCircle2 size={22} /><div><strong>Votre image est prête</strong><span>stegano-message.png · {formatBytes(result.size)}</span></div></div>
                    <button type="button" className="primary-action full-width" onClick={download}><Download size={17} /> TÉLÉCHARGER L’IMAGE PNG</button>
                    <p className="result-warning"><AlertTriangle size={16} /> <span>Envoyez-la <b>comme fichier ou document</b>, pas comme photo : WhatsApp, Messenger, Facebook ou Instagram la recompressent et détruisent le message caché.</span></p>
                    <button type="button" className="download-action" onClick={testDecode}><ScanLine size={16} /> TESTER LE DÉCODAGE DE CETTE IMAGE</button>
                  </div>
                )}
              </> : <>
                <StepTitle n={2} title="Clé secrète" done={!!password} hint="MÊME CLÉ QUE L’ENCODAGE" />
                <label className="field-label" htmlFor="decode-key">CLÉ</label>
                {keyInput("decode-key", password, setPassword, "Entrez la clé de déchiffrement")}
                <button className="primary-action full-width" onClick={() => void decode()} disabled={isBusy || !!decodeBlocker} aria-describedby="action-reason">
                  {isBusy ? <><span className="loading-spinner" /> DÉCHIFFREMENT EN COURS…</> : <><ScanLine size={17} /> LIRE ET DÉCHIFFRER</>}
                </button>
                <p className="action-reason" id="action-reason">{isBusy ? "" : decodeBlocker ?? ""}</p>
                {statusBlock}
                {decodedFile ? <div className="decoded-file-preview">
                  {decodedFile.kind === "image" && <img src={decodedFile.url} alt="Image décodée" />}
                  {decodedFile.kind === "audio" && <audio controls src={decodedFile.url} />}
                  {decodedFile.kind === "video" && <video controls src={decodedFile.url} />}
                  <div className="decoded-file-meta"><span>{decodedFile.filename}</span><span>{formatBytes(decodedFile.size)}</span></div>
                </div> : <>
                  <label className="field-label" htmlFor="decoded-message">MESSAGE DÉCODÉ</label>
                  <textarea id="decoded-message" className="decoded-message-area" value={decodedMessage} readOnly placeholder="Le message décodé apparaîtra ici…" rows={12} />
                </>}
                <div className="text-actions">
                  {decodedFile ? <button className="download-action text-download" onClick={downloadDecodedFile} disabled={isBusy}><Download size={16} /> TÉLÉCHARGER LE FICHIER</button> : <>
                    <button className="download-action text-download" onClick={() => void copyDecodedText()} disabled={!decodedMessage || isBusy}><Copy size={16} /> COPIER LE MESSAGE</button>
                    <button className="download-action text-download" onClick={saveDecodedText} disabled={!decodedMessage || isBusy}><Download size={16} /> ENREGISTRER EN .TXT</button>
                  </>}
                </div>
                {!decodedFile && <><label className="field-label filename-label" htmlFor="text-filename">NOM DU FICHIER <span>.TXT</span></label><div className="filename-field"><input id="text-filename" value={textFilename} onChange={(event) => setTextFilename(event.target.value)} /><span>.txt</span></div></>}
              </>}
            </div>
          </div>
        </div>
      </section>

      {toast && <div className="toast" role="status"><Check size={15} /> {toast}</div>}
      <footer className="footer"><span>STEGANO WEB / ATELIER LOCAL</span><span>Les données ne quittent jamais votre navigateur.</span><a href="?admin=1" style={{ opacity: 0.35 }}>admin</a><span>© 2026</span></footer>
    </main>
  );
}
