/**
 * CBC CIPHER — script.js
 * Logic dikonversi dari: ENKRIPSI_DAN_DEKRIPSI_KRIPTOGRAFI_CBC_FINAL.c
 *
 * Algoritma Enkripsi (per byte):
 *   1. XOR dengan byte sebelumnya / IV=0xAA  → CBC chaining
 *   2. XOR dengan karakter key (cyclic)       → Substitute
 *   3. Rotate Left 1 bit (sirkular)           → Permutasi
 *
 * Algoritma Dekripsi (urutan terbalik):
 *   1. Rotate Right 1 bit
 *   2. XOR dengan karakter key
 *   3. XOR dengan ciphertext byte sebelumnya / IV=0xAA
 */

/* ============================================================
   KONSTANTA
   ============================================================ */
const IV = 0xaa; // 10101010

/* ============================================================
   UTILITAS BIT
   ============================================================ */

/**
 * rotateLeft: circular rotate kiri 1 bit pada nilai 8-bit.
 * Contoh: 10001001 → 00010011
 */
function rotateLeft(b) {
  return ((b << 1) | (b >> 7)) & 0xff;
}

/**
 * rotateRight: kebalikan rotateLeft, dipakai saat dekripsi.
 * Contoh: 00010011 → 10001001
 */
function rotateRight(b) {
  return ((b >> 1) | (b << 7)) & 0xff;
}

/** Konversi byte ke string biner 8-bit dengan zero-padding */
function toBin(b) {
  return b.toString(2).padStart(8, "0");
}

/** Konversi array byte ke string biner dipisah spasi */
function toBinStr(bytes) {
  return Array.from(bytes).map(toBin).join(" ");
}

/**
 * idxToChar: petakan indeks 0–51 ke huruf A-Z / a-z.
 */
function idxToChar(idx) {
  return idx < 26
    ? String.fromCharCode(65 + idx)
    : String.fromCharCode(97 + idx - 26);
}

/**
 * charToIdx: petakan huruf A-Z / a-z ke indeks 0–51.
 */
function charToIdx(c) {
  return c >= "A" && c <= "Z" ? c.charCodeAt(0) - 65 : c.charCodeAt(0) - 97 + 26;
}

/**
 * toHuruf: enkode setiap byte ciphertext menjadi 2 huruf (A-Z/a-z).
 * Menggunakan basis-52: byte = hi*52 + lo  →  2 karakter huruf.
 * Lossless: 52² = 2704 > 256, jadi semua nilai byte 0–255 ter-cover.
 * Contoh: byte 200 → hi=3 (D), lo=44 (r) → "Dr"
 */
function toHuruf(bytes) {
  return Array.from(bytes)
    .map((b) => idxToChar(Math.floor(b / 52)) + idxToChar(b % 52))
    .join("");
}

/* ============================================================
   ENKRIPSI
   ============================================================ */

/**
 * encrypt: enkripsi array byte menggunakan CBC mode.
 * Mengembalikan { cipher: Uint8Array, steps: Array }
 */
function encrypt(plain, key) {
  const cipher = new Uint8Array(plain.length);
  let prev = IV;
  const steps = [];

  for (let i = 0; i < plain.length; i++) {
    const xorPrev = plain[i] ^ prev; // Langkah 1: CBC XOR
    const xorKey = xorPrev ^ key.charCodeAt(i % key.length); // Langkah 2: Substitute
    const rot = rotateLeft(xorKey); // Langkah 3: Rotate Left
    cipher[i] = rot;
    prev = rot;

    steps.push({
      idx: i + 1,
      plain: plain[i],
      xorPrev: xorPrev,
      xorKey: xorKey,
      rot: rot,
      cipher: rot,
    });
  }

  return { cipher, steps };
}

/* ============================================================
   DEKRIPSI
   ============================================================ */

/**
 * decrypt: dekripsi array byte ciphertext kembali ke plaintext.
 * Membalik ketiga langkah enkripsi dengan urutan terbalik.
 * Mengembalikan { plain: Uint8Array, steps: Array }
 */
function decrypt(cipher, key) {
  const plain = new Uint8Array(cipher.length);
  let prev = IV;
  const steps = [];

  for (let i = 0; i < cipher.length; i++) {
    const cb = cipher[i];
    const rotInv = rotateRight(cb); // Langkah 1: Rotate Right
    const xorKey = rotInv ^ key.charCodeAt(i % key.length); // Langkah 2: Rev Substitute
    const xorPrev = xorKey ^ prev; // Langkah 3: Balik CBC XOR
    plain[i] = xorPrev;
    prev = cb; // PENTING: pakai ciphertext ASLI

    steps.push({
      idx: i + 1,
      cipher: cb,
      rotInv: rotInv,
      xorKey: xorKey,
      xorPrev: xorPrev,
      plain: xorPrev,
    });
  }

  return { plain, steps };
}

/* ============================================================
   PARSING INPUT
   ============================================================ */

/**
 * parseBinary: konversi string biner (boleh ada spasi) ke Uint8Array.
 * Panjang bit harus kelipatan 8.
 */
function parseBinary(text) {
  const clean = text.replace(/\s/g, "");
  if (!/^[01]+$/.test(clean)) {
    return { err: "Input hanya boleh karakter 0 dan 1." };
  }
  if (clean.length % 8 !== 0) {
    return {
      err: `Panjang bit harus kelipatan 8. Saat ini: ${clean.length} bit (sisa ${clean.length % 8}).`,
    };
  }
  const bytes = new Uint8Array(clean.length / 8);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 8, i * 8 + 8), 2);
  }
  return { bytes };
}

/**
 * parseHuruf: konversi pasangan huruf A-Z/a-z (2 karakter per byte) ke Uint8Array.
 * Kebalikan dari toHuruf: setiap 2 huruf → 1 byte.
 */
function parseHuruf(text) {
  if (!/^[A-Za-z]+$/.test(text)) {
    return { err: "Input huruf hanya boleh A-Z dan a-z." };
  }
  if (text.length % 2 !== 0) {
    return {
      err: `Panjang huruf harus genap (2 karakter per byte). Saat ini: ${text.length} karakter.`,
    };
  }
  const bytes = new Uint8Array(text.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const hi = charToIdx(text[i * 2]);
    const lo = charToIdx(text[i * 2 + 1]);
    const val = hi * 52 + lo;
    if (val > 255) {
      return { err: `Nilai byte tidak valid di posisi ${i + 1}: '${text[i*2]}${text[i*2+1]}' (nilai ${val} > 255).` };
    }
    bytes[i] = val;
  }
  return { bytes };
}

/* ============================================================
   UI HELPERS
   ============================================================ */

function showError(id, msg) {
  const el = document.getElementById(id);
  el.textContent = "! ERROR: " + msg;
  el.style.display = "block";
}

function hideError(id) {
  document.getElementById(id).style.display = "none";
}

function showResult(id) {
  document.getElementById(id).style.display = "block";
}

function hideResult(id) {
  document.getElementById(id).style.display = "none";
}

function setText(id, val) {
  document.getElementById(id).textContent = val;
}

/** Salin teks elemen ke clipboard */
function cp(id) {
  const txt = document.getElementById(id).textContent;
  navigator.clipboard.writeText(txt).then(() => {
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = "OK!";
    setTimeout(() => (btn.textContent = orig), 1000);
  });
}

/** Tampilkan biner plaintext secara real-time saat mengetik */
function showPlainBin() {
  const val = document.getElementById("enc-plain").value;
  const el = document.getElementById("enc-plain-bin");
  if (!val) {
    el.textContent = "-";
    return;
  }
  el.textContent = Array.from(val)
    .map((c) => toBin(c.charCodeAt(0)))
    .join(" ");
}

/** Update label ciphertext sesuai format yang dipilih */
function updateDecLabel() {
  const fmt = document.querySelector('input[name="dec-fmt"]:checked').value;
  const label = document.getElementById("dec-cipher-label");
  const ta = document.getElementById("dec-cipher");
  if (fmt === "binary") {
    label.textContent = "CIPHERTEXT (BINER):";
    ta.placeholder = "Contoh: 00010011 10110110 ...";
  } else {
    label.textContent = "CIPHERTEXT (HURUF A-Z/a-z):";
    ta.placeholder = "Contoh huruf: DrmQAb ... (2 karakter per byte)";
  }
}

/* ============================================================
   TABS
   ============================================================ */

function switchTab(tab) {
  document.querySelectorAll(".tab").forEach((t, i) => {
    t.classList.toggle(
      "active",
      (i === 0 && tab === "encrypt") || (i === 1 && tab === "decrypt"),
    );
  });
  document
    .getElementById("panel-encrypt")
    .classList.toggle("active", tab === "encrypt");
  document
    .getElementById("panel-decrypt")
    .classList.toggle("active", tab === "decrypt");
}

/* ============================================================
   RUN ENKRIPSI
   ============================================================ */

function runEncrypt() {
  hideError("enc-error");
  hideResult("enc-result");

  const plainText = document.getElementById("enc-plain").value;
  const key = document.getElementById("enc-key").value;

  if (!plainText) {
    showError("enc-error", "Plaintext tidak boleh kosong.");
    return;
  }
  if (!key) {
    showError("enc-error", "Key tidak boleh kosong.");
    return;
  }

  // Validasi ASCII printable (32–126)
  for (let i = 0; i < plainText.length; i++) {
    const c = plainText.charCodeAt(i);
    if (c < 32 || c > 126) {
      showError(
        "enc-error",
        `Karakter tidak valid di posisi ${i + 1}: '${plainText[i]}'`,
      );
      return;
    }
  }

  const plain = new Uint8Array([...plainText].map((c) => c.charCodeAt(0)));
  const { cipher, steps } = encrypt(plain, key);

  setText("r-plain-ascii", plainText);
  setText("r-plain-bin", toBinStr(plain));
  setText("r-key", key);
  setText("r-cipher-bin", toBinStr(cipher));
  setText("r-cipher-huruf", toHuruf(cipher));

  // Tabel visualisasi enkripsi
  const tbody = document.getElementById("enc-viz");
  tbody.innerHTML = "";
  steps.forEach((s) => {
    const prevLabel = s.idx === 1 ? "IV(0xAA)" : `C[${s.idx - 1}]`;
    const plainChar = String.fromCharCode(s.plain);
    tbody.innerHTML += `
      <tr>
        <td>${s.idx}</td>
        <td class="p-cell">${plainChar} (${toBin(s.plain)})</td>
        <td>${toBin(s.xorPrev)} [⊕${prevLabel}]</td>
        <td>${toBin(s.xorKey)}</td>
        <td>${toBin(s.rot)}</td>
        <td class="c-cell">${toBin(s.cipher)}</td>
      </tr>`;
  });

  showResult("enc-result");
}

/* ============================================================
   RUN DEKRIPSI
   ============================================================ */

function runDecrypt() {
  hideError("dec-error");
  hideResult("dec-result");

  const fmt = document.querySelector('input[name="dec-fmt"]:checked').value;
  const cipherText = document.getElementById("dec-cipher").value.trim();
  const key = document.getElementById("dec-key").value;

  if (!cipherText) {
    showError("dec-error", "Ciphertext tidak boleh kosong.");
    return;
  }
  if (!key) {
    showError("dec-error", "Key tidak boleh kosong.");
    return;
  }

  let cipherBytes;
  if (fmt === "binary") {
    const res = parseBinary(cipherText);
    if (res.err) {
      showError("dec-error", res.err);
      return;
    }
    cipherBytes = res.bytes;
  } else {
    const res = parseHuruf(cipherText);
    if (res.err) {
      showError("dec-error", res.err);
      return;
    }
    cipherBytes = res.bytes;
  }

  const { plain, steps } = decrypt(cipherBytes, key);

  // Tampilkan ASCII plaintext (non-printable tampil sebagai [n])
  let plainStr = "";
  plain.forEach((b) => {
    plainStr += b >= 32 && b <= 126 ? String.fromCharCode(b) : `[${b}]`;
  });

  setText("d-cipher-huruf", toHuruf(cipherBytes));
  setText("d-cipher-bin", toBinStr(cipherBytes));
  setText("d-key", key);
  setText("d-plain-ascii", plainStr);

  // Tabel visualisasi dekripsi
  const tbody = document.getElementById("dec-viz");
  tbody.innerHTML = "";
  steps.forEach((s) => {
    const prevLabel = s.idx === 1 ? "IV(0xAA)" : `C[${s.idx - 1}]`;
    const plainChar =
      s.plain >= 32 && s.plain <= 126
        ? String.fromCharCode(s.plain)
        : `[${s.plain}]`;
    tbody.innerHTML += `
      <tr>
        <td>${s.idx}</td>
        <td class="c-cell">${toBin(s.cipher)}</td>
        <td>${toBin(s.rotInv)}</td>
        <td>${toBin(s.xorKey)}</td>
        <td>${toBin(s.xorPrev)} [⊕${prevLabel}]</td>
        <td class="p-cell">${plainChar} (${toBin(s.plain)})</td>
      </tr>`;
  });

  showResult("dec-result");
}
