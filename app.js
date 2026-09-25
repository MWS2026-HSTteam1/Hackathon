const $ = id => document.getElementById(id);
const fields = ["companyName", "orgType", "industryMajor", "tse33", "businessSector", "sector", "criticalFunctions", "affectedCount", "countConfidence", "leakStatus", "personalData", "sensitive", "financial", "myNumber", "credentials", "medicalData", "confidential", "malicious", "humanError", "serviceDown", "outsourced", "ongoing", "facts"];
const EVENT_LABELS = {
    unauthorized: "不正アクセス",
    malware: "マルウェア感染",
    ransomware: "ランサムウェア",
    misdelivery: "誤送信・誤公開",
    lost: "端末・媒体の紛失",
    insider: "内部不正",
    vulnerability: "脆弱性悪用・発見",
    ddos: "DDoS・サービス妨害",
    supplychain: "委託先・サプライチェーン",
    other: "その他・未分類"
};
const emptyCase = {
    caseName: "新規インシデント",
    companyName: "",
    orgType: "private",
    industryMajor: "other",
    tse33: "",
    businessSector: "",
    sector: "general",
    criticalFunctions: "",
    events: [],
    affectedCount: 0,
    countConfidence: "unknown",
    leakStatus: "unknown",
    personalData: false,
    sensitive: false,
    financial: false,
    myNumber: false,
    credentials: false,
    medicalData: false,
    confidential: false,
    malicious: false,
    humanError: false,
    serviceDown: false,
    outsourced: false,
    ongoing: false,
    facts: ""
};
const presets = {
    blank: emptyCase,
    mistake: {
        ...emptyCase,
        caseName: "顧客情報の誤送信",
        companyName: "サンプル事業株式会社",
        businessSector: "BtoBサービス",
        industryMajor: "services",
        tse33: "サービス業",
        events: ["misdelivery"],
        affectedCount: 8,
        countConfidence: "confirmed",
        leakStatus: "confirmed",
        personalData: true,
        humanError: true,
        facts: "顧客8名分の氏名とメールアドレスを別の取引先1社へ誤送信。受信者へ削除を依頼し、削除済みとの回答を得た。"
    },
    ecommerce: {
        ...emptyCase,
        caseName: "ECサイト不正アクセス事案",
        companyName: "サンプルEC株式会社",
        industryMajor: "commerce",
        tse33: "小売業",
        businessSector: "EC・小売",
        sector: "retail",
        criticalFunctions: "EC販売、受注、決済、物流、顧客対応",
        events: ["unauthorized"],
        affectedCount: 4200,
        countConfidence: "max",
        leakStatus: "suspected",
        personalData: true,
        financial: true,
        credentials: true,
        malicious: true,
        outsourced: true,
        ongoing: true,
        facts: "外部IPアドレスから管理画面への不正ログインを確認。顧客情報の検索履歴があり、カード情報を含むレコードへのアクセスと外部送信量を調査中。"
    },
    hospital: {
        ...emptyCase,
        caseName: "電子カルテ・ランサムウェア事案",
        companyName: "サンプル総合病院",
        orgType: "medical",
        industryMajor: "services",
        businessSector: "総合病院・医療",
        sector: "healthcare",
        criticalFunctions: "診療、救急、電子カルテ、検査、薬剤、患者受付",
        events: ["ransomware", "malware"],
        affectedCount: 18000,
        countConfidence: "max",
        leakStatus: "suspected",
        personalData: true,
        sensitive: true,
        medicalData: true,
        malicious: true,
        serviceDown: true,
        outsourced: true,
        ongoing: true,
        facts: "電子カルテ関連サーバーが暗号化され、一部診療業務が停止。攻撃者はデータ窃取を主張しているが、外部送信の証拠を精査中。"
    }
};
let answers = {
    exfil: "unknown",
    containment: "unknown",
    dataScope: "unknown",
    contract: "unknown"
}, current, audit = [], plan = [];

function setDefaultDate() {
    if (!$("detectedAt").value) {
        const d = new Date(Date.now() - 7200000);
        d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
        $("detectedAt").value = d.toISOString().slice(0, 16)
    }
}
function readForm() {
    const d = {
        caseName: $("caseName").value.trim(),
        detectedAt: $("detectedAt").value,
        phase: $("phase").value,
        events: [...document.querySelectorAll('[name="incidentEvent"]:checked')].map(e => e.value)
    };
    fields.forEach(k => {
        const e = $(k);
        d[k] = e.type === "checkbox" ? e.checked : e.type === "number" ? Number(e.value || 0) : e.value
    }
    );
    return d
}
function fill(data) {
    const events = data.events || (data.incidentType ? [data.incidentType] : []);
    document.querySelectorAll('[name="incidentEvent"]').forEach(e => e.checked = events.includes(e.value));
    Object.entries(data).forEach( ([k,v]) => {
        const e = $(k);
        if (e)
            e.type === "checkbox" ? e.checked = Boolean(v) : e.value = v
    }
    )
}
function esc(s) {
    return String(s).replace(/[&<>'"]/g, c => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        "'": "&#39;",
        '"': "&quot;"
    }[c]))
}
function addDays(date, n) {
    const d = new Date(date);
    d.setDate(d.getDate() + n);
    return d
}
function fmtDate(d) {
    return new Intl.DateTimeFormat("ja-JP",{
        month: "numeric",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit"
    }).format(d)
}
function remain(date) {
    const h = Math.ceil((date - Date.now()) / 3600000);
    return h < 0 ? `${Math.ceil(Math.abs(h) / 24)}日超過` : h < 24 ? `残り約${h}時間` : `残り約${Math.ceil(h / 24)}日`
}

function analyze(d) {
    const threshold = 1000
      , hasEvent = d.events.length > 0
      , hasPersonal = Boolean(d.personalData || d.sensitive || d.financial || d.myNumber || d.medicalData || d.credentials);
    const riskExists = ["confirmed", "suspected"].includes(d.leakStatus) || answers.exfil === "yes";
    const trigger = Boolean(d.sensitive || d.financial || d.malicious || d.affectedCount > threshold);
    const reportable = hasPersonal && riskExists && trigger;
    const pending = !reportable && hasPersonal && (d.leakStatus === "unknown" || d.countConfidence === "unknown" || (d.leakStatus === "suspected" && answers.exfil === "unknown"));
    const reasons = [];
    if (!hasEvent)
        reasons.push("発生事象が未選択のため、インシデント類型を確認する必要がある");
    if (!hasPersonal)
        reasons.push("個人データに関する影響が選択されていないため、PPC報告は判定対象外");
    if (d.sensitive || d.medicalData)
        reasons.push("要配慮個人情報・医療情報を含む可能性");
    if (d.financial)
        reasons.push("不正利用により財産的被害が生じるおそれのある情報を含む");
    if (d.malicious)
        reasons.push("不正目的の行為による漏えい等、またはそのおそれに該当する可能性");
    if (d.affectedCount > threshold)
        reasons.push(`${threshold.toLocaleString()}人を超える本人が対象となる可能性`);
    if (d.leakStatus === "unknown")
        reasons.push("漏えい・滅失・毀損の有無が未確認のため、判定を保留");
    if (d.countConfidence === "unknown" && hasPersonal)
        reasons.push("対象人数が未確認のため、件数要件を確定できない");
    if (d.leakStatus === "unlikely" && answers.exfil !== "yes")
        reasons.push("現時点では漏えい等またはそのおそれを示す事実を確認できない");
    if (d.orgType === "government")
        reasons.push("行政機関等は適用法令・所管窓口を別途確認する必要がある");
    if (d.orgType === "medical")
        reasons.push("医療機関として患者安全・診療継続・医療情報への影響を並行評価する必要がある");
    if (d.orgType === "education_org")
        reasons.push("教育・研究機関として学生・教職員情報と教育研究継続への影響を並行評価する必要がある");
    if (d.tse33)
        reasons.push(`企業プロファイル：東証33業種「${d.tse33}」、事業セクター「${d.businessSector || "未確認"}」`);
    if (d.myNumber)
        reasons.push("マイナンバーを含む、または不明のため専用報告経路の確認が必要");
    if (answers.exfil === "yes" && d.leakStatus !== "confirmed")
        reasons.push("追加確認により第三者への外部送信を確認");
    const score = (d.sensitive || d.medicalData ? 2 : 0) + (d.financial || d.credentials ? 2 : 0) + (d.malicious ? 2 : 0) + (d.affectedCount > threshold ? 2 : d.affectedCount ? 1 : 0) + (d.serviceDown ? 2 : 0) + (d.ongoing ? 2 : 0) + (d.leakStatus === "confirmed" ? 2 : d.leakStatus === "suspected" ? 1 : 0) + (answers.exfil === "yes" ? 2 : 0);
    const severity = score >= 10 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low";
    const detected = new Date(d.detectedAt || Date.now())
      , initialStart = addDays(detected, 3)
      , initialEnd = addDays(detected, 5)
      , final = addDays(detected, d.malicious ? 60 : 30);
    const questions = [];
    if (hasPersonal && d.leakStatus !== "not_applicable")
        questions.push({
            id: "exfil",
            title: "外部送信・第三者閲覧の証跡",
            text: "通信ログ、検索履歴、クラウド監査ログ等で確認できたか",
            impact: "回答により漏えい可能性と通知方針を更新"
        });
    if (hasPersonal && (d.countConfidence !== "confirmed" || d.affectedCount === 0))
        questions.push({
            id: "dataScope",
            title: "情報項目と人数の確定",
            text: "対象データ、情報項目、重複排除後の本人件数を確定したか",
            impact: "件数要件・確報・本人通知の前提"
        });
    if (d.malicious || d.ongoing || d.serviceDown)
        questions.push({
            id: "containment",
            title: "封じ込めと業務継続",
            text: "侵入口の遮断、認証情報の無効化、証拠保全、代替業務を確認したか",
            impact: "対外説明と復旧判断に反映"
        });
    if (d.outsourced || d.events.includes("supplychain"))
        questions.push({
            id: "contract",
            title: "委託契約・連絡経路",
            text: "契約上の報告期限、責任分界、連絡窓口を確認したか",
            impact: "委託元・委託先への連絡漏れを防止"
        });
    const actions = [];
    if (d.serviceDown)
        actions.push("安全な業務継続と証拠保全を両立する");
    actions.push("確認済み事実・推測・未確認事項を分けて記録");
    if (reportable || pending)
        actions.push("法務・個人情報保護責任者と報告要否をレビュー");
    if (d.outsourced)
        actions.push("委託元・委託先の契約期限と連絡先を確認");
    if (d.sector !== "general")
        actions.push("業界固有の所管省庁・ガイドラインを確認");
    if (d.malicious)
        actions.push("警察・JPCERT/CC等への相談要否を検討");
    if (d.sector === "manufacturing")
        actions.push("製造・品質保証・受発注・物流の停止影響を事業継続部門と確認");
    if (d.sector === "healthcare")
        actions.push("患者安全と診療継続を最優先に、医療情報への影響を分離して評価");
    if (d.sector === "finance")
        actions.push("決済・顧客資産・取引継続と所管当局への連絡要否を確認");
    if (d.sector === "retail")
        actions.push("受注・決済・在庫・物流・顧客対応への波及を確認");
    const stakeholders = [{
        name: "経営層",
        priority: d.serviceDown || severity === "critical" ? "直ちに" : "初動整理後",
        disclose: "影響、期限、未確定事項、必要な意思決定",
        hold: "未検証の攻撃者属性・原因断定"
    }];
    if (hasPersonal)
        stakeholders.push({
            name: d.myNumber ? "PPC・マイナンバー報告窓口" : "PPC／権限委任先",
            priority: reportable ? "3〜5日目安" : pending ? "要否確認" : "継続監視",
            disclose: "発生状況、情報種類、件数、原因、対応",
            hold: "根拠のない断定・不要な内部情報"
        }, {
            name: "顧客・本人",
            priority: reportable ? "速やかに検討" : "要否確認",
            disclose: "影響、本人が取る対策、問い合わせ窓口",
            hold: "脆弱性詳細・第三者情報・推測"
        });
    if (d.malicious)
        stakeholders.push({
            name: "警察・JPCERT/CC",
            priority: "相談要否を確認",
            disclose: "攻撃事実、IoC、被害状況、支援依頼",
            hold: "不要な個人情報・未検証情報"
        });
    if (d.outsourced)
        stakeholders.push({
            name: "委託元・委託先",
            priority: "契約期限内",
            disclose: "契約上の報告事項、影響範囲、対応依頼",
            hold: "他顧客情報・不要な社内情報"
        });
    stakeholders.push({
        name: "広報・Web",
        priority: "公表判断後",
        disclose: "確認済み事実、影響、対応状況",
        hold: "侵入経路の詳細、調査中の推測"
    });
    const decision = reportable ? "報告対象の可能性が高い" : pending ? "情報不足のため判定保留" : hasPersonal ? "現時点では対象外の可能性" : "個人データ報告の判定対象外";
    return {
        d,
        threshold,
        hasPersonal,
        reportable,
        pending,
        reasons,
        severity,
        detected,
        initialStart,
        initialEnd,
        final,
        questions,
        actions,
        stakeholders,
        decision,
        nextOwner: d.serviceDown ? "危機対策本部・法務" : d.malicious ? "CSIRT責任者・法務" : "法務・個情責任者"
    };
}

function list(id, items) {
    $(id).innerHTML = items.map(x => `<li>${esc(x)}</li>`).join("")
}
function render(r) {
    current = r;
    $("severityBadge").className = `severity ${r.severity}`;
    $("severityBadge").textContent = r.severity.toUpperCase();
    $("reportDecision").textContent = r.decision;
    $("nextOwner").textContent = r.nextOwner;
    $("initialDeadline").textContent = r.reportable ? `${fmtDate(r.initialStart)}〜${fmtDate(r.initialEnd)}` : r.pending ? "要確認" : "法定期限なし";
    $("initialCountdown").textContent = r.reportable ? remain(r.initialEnd) : r.pending ? "不足情報を確認" : "継続監視";
    $("finalDeadline").textContent = r.reportable ? fmtDate(r.final) : r.pending ? "判定保留" : "—";
    $("finalCountdown").textContent = r.reportable ? remain(r.final) : "";
    list("reasons", r.reasons);
    list("actions", r.actions);
    renderQuestions(r);
    renderBasis(r);
    renderChecklist();
    renderTimeline(r);
    renderPlan(r);
    $("matrixRows").innerHTML = r.stakeholders.map(x => `<div class="matrix-row"><span><strong>${esc(x.name)}</strong><small>${esc(x.priority)}</small></span><span>${esc(x.disclose)}</span><span class="hold">${esc(x.hold)}</span></div>`).join("");
    renderDraft();
    $("saveState").textContent = "変更あり";
}
function renderQuestions(r) {
    const done = r.questions.filter(q => answers[q.id] !== "unknown").length
      , total = r.questions.length;
    $("questionCount").textContent = total - done;
    $("completion").textContent = total ? `${Math.round(done / total * 100)}% 完了` : "追加確認なし";
    $("questionCards").innerHTML = total ? r.questions.map(q => `<article class="question-card"><div><strong>${esc(q.title)}</strong><p>${esc(q.text)}</p><small>${esc(q.impact)}</small></div><div class="segmented" data-answer="${q.id}">${["yes", "no", "unknown"].map( (v, i) => `<button class="${answers[q.id] === v ? "active" : ""}" data-value="${v}">${["はい", "いいえ", "未確認"][i]}</button>`).join("")}</div></article>`).join("") : '<p class="empty">現在の入力から追加質問は生成されていません。</p>'
}
function renderBasis(r) {
    const confidence = r.d.countConfidence === "confirmed" ? "確定" : r.d.countConfidence === "max" ? "最大見込" : "未確認"
      , rules = [["個人データ関連", r.hasPersonal ? "matched" : "", r.hasPersonal ? "個人情報・決済・認証・医療等の影響が入力されています" : "個人データへの影響は未選択です"], ["漏えい等の状態", r.d.leakStatus === "unknown" ? "pending" : (["confirmed", "suspected"].includes(r.d.leakStatus) ? "matched" : ""), `現在の入力：${$("leakStatus").selectedOptions[0].textContent}`], ["要配慮・財産的被害", r.d.sensitive || r.d.medicalData || r.d.financial ? "matched" : "", "要配慮情報、医療情報、財産的被害のおそれ"], ["不正目的の行為", r.d.malicious ? "matched" : "", "不正アクセス、マルウェア、盗難、内部持出し等"], [`${r.threshold.toLocaleString()}人超`, r.d.countConfidence === "unknown" ? "pending" : (r.d.affectedCount > r.threshold ? "matched" : ""), `入力値：${r.d.affectedCount.toLocaleString()}人（${confidence}）`]];
    $("basisCards").innerHTML = rules.map( ([t,state,desc], i) => `<article class="basis-card ${state}"><span>${state === "matched" ? "該当" : state === "pending" ? "未確認" : "非該当"}</span><div><strong>要件 ${i + 1}｜${esc(t)}</strong><p>${esc(desc)}</p></div></article>`).join("") + `<article class="basis-card deadline"><span>期限</span><div><strong>${r.reportable ? "速報は発覚後速やかに（目安3〜5日）、確報は30日以内" : "報告要否の確定後に期限を起算"}</strong><p>不正目的の行為によるおそれがある場合は確報60日以内。最終判断は責任者が行います。</p></div></article>`
}
function renderChecklist() {
    const tasks = [["インシデント責任者を確定", true], ["証拠保全・封じ込め", answers.containment === "yes"], ["対象情報・人数を確定", answers.dataScope === "yes"], ["速報ドラフトをレビュー", false], ["本人通知・公表判断", false]];
    $("checklist").innerHTML = tasks.map( ([t,on]) => `<label><input type="checkbox" ${on ? "checked" : ""}>${esc(t)}</label>`).join("")
}
function renderTimeline(r) {
    const rows = r.reportable ? [["発覚", r.detected, "事実整理・責任者招集"], ["速報目安", r.initialEnd, "監督機関への速報を検討"], ["確報期限", r.final, "調査結果・再発防止を報告"]] : [["発覚", r.detected, "事実整理・責任者招集"], ["一次レビュー", addDays(r.detected, 1), r.pending ? "不足情報を確認し報告要否を再判定" : "影響範囲と対応方針を確認"], ["再評価", addDays(r.detected, 3), "新事実・影響拡大の有無を確認"]];
    $("timeline").innerHTML = rows.map( ([l,d,t], i) => `<div class="time-node ${i === 0 ? "done" : ""}"><span></span><div><small>${l}</small><strong>${fmtDate(d)}</strong><p>${t}</p></div></div>`).join("")
}
function isoDate(d) {
    const x = new Date(d);
    return `${x.getFullYear()}-${String(x.getMonth() + 1).padStart(2, "0")}-${String(x.getDate()).padStart(2, "0")}`
}
function task(owner, work, start, due, status="未着手", depends="") {
    return {
        owner,
        work,
        start: isoDate(start),
        due: isoDate(due),
        status,
        depends
    }
}
function generatePlan(r) {
    const d = r.detected
      , day = n => addDays(d, n)
      , before = (base, n) => addDays(base, -n)
      , tasks = [task("CSIRT責任者", "初動指揮・確認済み事実の整理", d, d, "対応中"), task("解析担当", "証拠保全と影響範囲・侵入経路の調査", d, day(2), "対応中", "初動指揮"), task("法務・個人情報保護責任者", "法令・契約上の報告要否を一次判断", d, day(1), "対応中", "初動情報"), task("CSIRT責任者", "未確認事項の担当割当と再評価", day(1), day(3), "未着手", "一次判断")];
    if (r.reportable)
        tasks.push(task("法務", "速報内容・開示範囲のレビュー", day(1), before(r.initialEnd, 1), "未着手", "報告要否判断"), task("CSIRT／報告担当", "監督機関への速報提出", before(r.initialEnd, 1), r.initialEnd, "未着手", "法務レビュー"), task("広報・顧客対応", "本人通知案・FAQ・問い合わせ窓口の準備", r.initialStart, addDays(r.initialEnd, 2), "未着手", "影響範囲"), task("解析担当", "原因・対象情報・本人件数の確定", day(1), before(r.final, 7), "未着手", "証拠保全"), task("CSIRT", "確報案と再発防止策の取りまとめ", before(r.final, 7), before(r.final, 2), "未着手", "詳細調査"), task("法務・個情責任者", "確報の承認・提出", before(r.final, 2), r.final, "未着手", "確報案"));
    else
        tasks.push(task("CSIRT・所管部門", "影響拡大の監視とクローズ条件の確認", day(1), day(5), "未着手", "一次判断"), task("CSIRT", "原因・再発防止策の取りまとめ", day(2), day(7), "未着手", "詳細調査"));
    if (r.d.outsourced)
        tasks.splice(4, 0, task("委託管理担当", "委託先への調査依頼・契約期限の確認", d, day(1), "未着手", "初動情報"));
    if (r.d.serviceDown)
        tasks.splice(1, 0, task("事業継続責任者", "安全な業務継続・復旧方針の決定", d, day(1), "対応中", "初動指揮"));
    return tasks;
}
function renderPlan(r) {
    plan = generatePlan(r);
    $("planDetected").textContent = isoDate(r.detected);
    $("planInitial").textContent = r.reportable ? `${isoDate(r.initialStart)}〜${isoDate(r.initialEnd)}` : r.pending ? "要確認" : "法定期限なし";
    $("planFinal").textContent = r.reportable ? isoDate(r.final) : r.pending ? "判定後に設定" : "継続監視";
    $("planRows").innerHTML = plan.map( (t, i) => `<tr data-row="${i}"><td><input data-key="owner" value="${esc(t.owner)}"></td><td><input data-key="work" value="${esc(t.work)}"></td><td><input data-key="start" type="date" value="${t.start}"></td><td><input data-key="due" type="date" value="${t.due}"></td><td><select data-key="status">${["未着手", "対応中", "完了", "遅延"].map(s => `<option ${s === t.status ? "selected" : ""}>${s}</option>`).join("")}</select></td></tr>`).join("");
}
function collectPlan() {
    document.querySelectorAll("#planRows tr").forEach(tr => {
        const i = Number(tr.dataset.row);
        tr.querySelectorAll("[data-key]").forEach(e => plan[i][e.dataset.key] = e.value)
    }
    );
    return plan
}
function buildDrafts() {
    if (!current)
        return {};
    const r = current
      , d = r.d
      , type = d.events.length ? d.events.map(x => EVENT_LABELS[x] || x).join("、") : "未分類・確認中"
      , common = `案件：${d.caseName}\n企業・組織：${d.companyName || "未入力"}\n業種：${d.tse33 || "東証区分なし"}／${d.businessSector || "未判定"}\n重要業務：${d.criticalFunctions || "未確認"}\n発覚：${fmtDate(r.detected)}\n事案：${type}\n対象：${d.affectedCount.toLocaleString()}名（${d.countConfidence === "confirmed" ? "確定" : d.countConfidence === "max" ? "最大見込" : "未確認"}）\n状況：${d.facts || "事実関係を確認中"}`;
    return {
        executive: `【インシデント第一報】\n\n${common}\n\n■一次判断\n法定報告：${r.decision}\n速報目安：${r.reportable ? fmtDate(r.initialStart) + "〜" + fmtDate(r.initialEnd) : "該当なし"}\n確報期限：${r.reportable ? fmtDate(r.final) : "該当なし"}\n\n■判断を求める事項\n・調査、封じ込め体制\n・対外説明の方針と承認者\n・サービス継続／停止判断\n\n※確認済み事実と未確認事項を分け、調査進展に応じて更新します。`,
        authority: `【漏えい等事案・報告記載案】\n\n${common}\n\n■報告対象と判断した理由\n${r.reasons.map(x => "・" + x).join("\n")}\n\n■実施中の対応\n・影響範囲と外部送信の調査\n・関係システムの保全とアクセス制御\n・本人件数と情報項目の確認\n\n本案は提出前に責任者の確認を要します。`,
        customer: `【重要】情報セキュリティ事案に関するお知らせ\n\n当社において、${type}に関する事象を確認しました。\n\n現在確認している内容：\n${d.facts}\n\n対象となる可能性がある方には必要な対応を個別にご案内します。不審な連絡や身に覚えのないログインにご注意ください。`,
        vendor: `【至急／調査依頼】${d.caseName}\n\n${common}\n\n以下を至急ご回答ください。\n1. 貴社環境における影響有無と検知日時\n2. 関連ログの保全状況と提出予定\n3. 外部送信・第三者閲覧の有無\n4. 封じ込め状況と再発可能性\n5. 契約上の報告窓口・責任者\n\n推測を含む場合は確認済み事実と区別してください。`
    }
}
function setDraftMode(mode, message) {
    const badge = $("draftMode");
    badge.className = `mode-badge ${mode}`;
    badge.textContent = mode === "ai" ? "LLM生成" : "ローカルテンプレート";
    $("draftNotice").textContent = message
}
function syncPrintDraft() {
    $("printDraft").textContent = $("draftText").value
}
function renderDraft() {
    if (!current)
        return;
    $("draftText").value = buildDrafts()[$("draftTarget").value];
    syncPrintDraft();
    setDraftMode("local", "外部送信なし。AI生成を選んだ場合のみ、画面上の事案情報をLLM APIへ送信します。")
}
async function generateAiDraft() {
    const button = $("aiDraftBtn")
      , target = $("draftTarget").value
      , original = button.innerHTML;
    button.disabled = true;
    button.textContent = "生成中…";
    setDraftMode("local", "LLMへ接続しています。利用できない場合は自動的にテンプレートへ戻します。");
    const payload = {
        target,
        case: {
            ...current.d,
            facts: String(current.d.facts || "").slice(0, 3000)
        },
        assessment: {
            decision: current.decision,
            severity: current.severity,
            reasons: current.reasons,
            deadlines: {
                initial: current.reportable ? `${isoDate(current.initialStart)}〜${isoDate(current.initialEnd)}` : null,
                final: current.reportable ? isoDate(current.final) : null
            },
            unknowns: current.questions.filter(q => answers[q.id] === "unknown").map(q => q.title)
        }
    };
    try {
        const response = await fetch("/api/generate", {
            method: "POST",
            headers: {
                "content-type": "application/json"
            },
            body: JSON.stringify(payload),
            signal: AbortSignal.timeout(20000)
        });
        if (!response.ok)
            throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (!data.text || typeof data.text !== "string")
            throw new Error("invalid response");
        $("draftText").value = data.text.trim();
        syncPrintDraft();
        setDraftMode("ai", `LLM生成済み（${data.model || "configured model"}）。提出前に責任者が確認してください。`);
        audit.unshift({
            time: new Date().toISOString(),
            event: `AI文案を生成：${target}`
        });
    } catch (error) {
        $("draftText").value = buildDrafts()[target];
        syncPrintDraft();
        setDraftMode("local", "LLM APIが未設定または利用できないため、ローカルテンプレートで生成しました。デモは継続できます。");
    } finally {
        button.disabled = false;
        button.innerHTML = original
    }
}

function colName(n) {
    let s = "";
    while (n) {
        n--;
        s = String.fromCharCode(65 + n % 26) + s;
        n = Math.floor(n / 26)
    }
    return s
}
function excelDate(v) {
    const d = new Date(v + "T00:00:00");
    return Math.floor((Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()) - Date.UTC(1899, 11, 30)) / 86400000)
}
function xCell(ref, value, style=4) {
    return `<c r="${ref}" s="${style}" t="inlineStr"><is><t xml:space="preserve">${esc(value ?? "")}</t></is></c>`
}
function nCell(ref, value, style=5) {
    return `<c r="${ref}" s="${style}"><v>${value}</v></c>`
}
function sheetXml(rows, lastCol, lastRow, cols, merge="", filter="") {
    return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><dimension ref="A1:${lastCol}${lastRow}"/><sheetViews><sheetView workbookViewId="0"><pane xSplit="2" ySplit="4" topLeftCell="C5" activePane="bottomRight" state="frozen"/></sheetView></sheetViews><sheetFormatPr defaultRowHeight="15"/><cols>${cols}</cols><sheetData>${rows}</sheetData>${filter}${merge}<pageMargins left="0.25" right="0.25" top="0.5" bottom="0.5" header="0.2" footer="0.2"/><pageSetup orientation="landscape" fitToWidth="1" fitToHeight="0"/></worksheet>`;
}
function ganttSheet() {
    const tasks = collectPlan()
      , dates = []
      , min = new Date(Math.min(...tasks.map(t => new Date(t.start + "T00:00:00"))))
      , max = new Date(Math.max(...tasks.map(t => new Date(t.due + "T00:00:00"))));
    for (let d = new Date(min); d <= max && dates.length < 92; d.setDate(d.getDate() + 1))
        dates.push(isoDate(d));
    const last = colName(6 + dates.length)
      , rows = [];
    rows.push(`<row r="1" ht="24"><c r="A1" s="1" t="inlineStr"><is><t>${esc(current.d.caseName)} 対応計画</t></is></c></row>`);
    rows.push(`<row r="2">${xCell("A2", "発覚", 4)}${xCell("B2", isoDate(current.detected), 4)}${xCell("C2", "速報目安", 4)}${xCell("D2", current.reportable ? isoDate(current.initialEnd) : "対象外の可能性", 4)}${xCell("E2", "確報期限", 4)}${xCell("F2", current.reportable ? isoDate(current.final) : "継続監視", 4)}</row>`);
    rows.push('<row r="3"></row>');
    let h = ["担当", "タスク", "開始日", "期限", "状態", "依存先"].map( (v, i) => xCell(colName(i + 1) + "4", v, 2)).join("");
    dates.forEach( (d, i) => h += nCell(colName(i + 7) + "4", excelDate(d), 3));
    rows.push(`<row r="4" ht="30" customHeight="1">${h}</row>`);
    tasks.forEach( (t, i) => {
        const r = i + 5;
        let cells = xCell("A" + r, t.owner) + xCell("B" + r, t.work) + nCell("C" + r, excelDate(t.start)) + nCell("D" + r, excelDate(t.due)) + xCell("E" + r, t.status) + xCell("F" + r, t.depends || "");
        const fill = {
            未着手: 6,
            対応中: 7,
            完了: 8,
            遅延: 9
        }[t.status] || 6;
        dates.forEach( (d, j) => {
            const ref = colName(j + 7) + r;
            cells += d >= t.start && d <= t.due ? xCell(ref, "", fill) : xCell(ref, "", 4)
        }
        );
        rows.push(`<row r="${r}" ht="24">${cells}</row>`)
    }
    );
    const cols = '<col min="1" max="1" width="20" customWidth="1"/><col min="2" max="2" width="42" customWidth="1"/><col min="3" max="4" width="13" customWidth="1"/><col min="5" max="5" width="12" customWidth="1"/><col min="6" max="6" width="18" customWidth="1"/>' + (`<col min="7" max="${6 + dates.length}" width="11.5" customWidth="1"/>`);
    return sheetXml(rows.join(""), last, tasks.length + 4, cols, `<mergeCells count="1"><mergeCell ref="A1:${last}1"/></mergeCells>`, `<autoFilter ref="A4:F${tasks.length + 4}"/>`);
}
function simpleSheet(title, headers, data, widths) {
    const rows = [`<row r="1" ht="24"><c r="A1" s="1" t="inlineStr"><is><t>${esc(title)}</t></is></c></row>`, '<row r="2"></row>', `<row r="3">${headers.map( (h, i) => xCell(colName(i + 1) + "3", h, 2)).join("")}</row>`];
    data.forEach( (row, i) => rows.push(`<row r="${i + 4}">${row.map( (v, j) => xCell(colName(j + 1) + (i + 4), v, 4)).join("")}</row>`));
    const cols = widths.map( (w, i) => `<col min="${i + 1}" max="${i + 1}" width="${w}" customWidth="1"/>`).join("");
    return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><dimension ref="A1:${colName(headers.length)}${data.length + 3}"/><sheetViews><sheetView workbookViewId="0"><pane ySplit="3" topLeftCell="A4" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><sheetFormatPr defaultRowHeight="15"/><cols>${cols}</cols><sheetData>${rows.join("")}</sheetData><autoFilter ref="A3:${colName(headers.length)}${data.length + 3}"/><mergeCells count="1"><mergeCell ref="A1:${colName(headers.length)}1"/></mergeCells><pageMargins left="0.4" right="0.4" top="0.5" bottom="0.5" header="0.2" footer="0.2"/></worksheet>`;
}
function workbookParts() {
    const raci = [["初動指揮", "A/R", "C", "C", "I", "I"], ["証拠保全・調査", "A", "R", "I", "I", "I"], ["報告要否判断", "C", "C", "A/R", "I", "I"], ["速報・確報提出", "R", "C", "A", "I", "I"], ["本人通知・公表", "C", "I", "C", "R", "A"], ["復旧・再発防止", "A", "R", "C", "I", "I"]];
    const unknown = current.questions.filter(q => answers[q.id] === "unknown").map(q => ["未確認事項", q.title, q.text]);
    const inputs = [["案件名", current.d.caseName, ""], ["企業・組織名", current.d.companyName || "未入力", "手動入力"], ["業種プロファイル", current.d.tse33 || "東証区分なし", `${current.d.businessSector || "未判定"}／${current.d.criticalFunctions || "重要業務未確認"}`], ["発覚日時", current.d.detectedAt, ""], ["組織種別", $("orgType").selectedOptions[0]?.textContent || current.d.orgType, ""], ["発生事象", current.d.events.map(x => EVENT_LABELS[x] || x).join("、") || "未選択", ""], ["対象人数", String(current.d.affectedCount), current.d.countConfidence], ["報告判断", current.decision, current.reasons.join("／")], ["速報目安", current.reportable ? `${isoDate(current.initialStart)}〜${isoDate(current.initialEnd)}` : current.pending ? "要確認" : "法定期限なし", ""], ["確報期限", current.reportable ? isoDate(current.final) : current.pending ? "判定後に設定" : "継続監視", ""], ["確認済み事実", current.d.facts || "未入力", ""], ...unknown, ["公的根拠", "個人情報保護委員会", "https://www.ppc.go.jp/personalinfo/legal/leakAction/"]];
    const types = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/worksheets/sheet3.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>`;
    const styles = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><numFmts count="2"><numFmt numFmtId="164" formatCode="yyyy-mm-dd"/><numFmt numFmtId="165" formatCode="yyyy-m-d"/></numFmts><fonts count="3"><font><sz val="10"/><name val="Arial"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="10"/><name val="Arial"/></font><font><b/><color rgb="FF071B33"/><sz val="14"/><name val="Arial"/></font></fonts><fills count="9"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF071B33"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FF1F6FEB"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FF35A874"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFD9E1E8"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFC53D46"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFF2B84B"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFE9F2FF"/></patternFill></fill></fills><borders count="2"><border/><border><left style="thin"><color rgb="FFD5E0EA"/></left><right style="thin"><color rgb="FFD5E0EA"/></right><top style="thin"><color rgb="FFD5E0EA"/></top><bottom style="thin"><color rgb="FFD5E0EA"/></bottom></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellStyleXfs><cellXfs count="11"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf numFmtId="165" fontId="1" fillId="2" borderId="1" xfId="0" applyNumberFormat="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyAlignment="1"><alignment vertical="center"/></xf><xf numFmtId="164" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1"/><xf numFmtId="0" fontId="0" fillId="5" borderId="1" xfId="0"/><xf numFmtId="0" fontId="0" fillId="3" borderId="1" xfId="0"/><xf numFmtId="0" fontId="0" fillId="4" borderId="1" xfId="0"/><xf numFmtId="0" fontId="0" fillId="6" borderId="1" xfId="0"/><xf numFmtId="0" fontId="0" fillId="7" borderId="1" xfId="0"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>`;
    return {
        "[Content_Types].xml": types,
        "_rels/.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>`,
        "xl/workbook.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="対応計画・ガント" sheetId="1" r:id="rId1"/><sheet name="RACI" sheetId="2" r:id="rId2"/><sheet name="前提・未確認事項" sheetId="3" r:id="rId3"/></sheets><calcPr calcId="191029"/></workbook>`,
        "xl/_rels/workbook.xml.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet3.xml"/><Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`,
        "xl/styles.xml": styles,
        "xl/worksheets/sheet1.xml": ganttSheet(),
        "xl/worksheets/sheet2.xml": simpleSheet("役割分担（RACI）", ["タスク", "CSIRT", "解析", "法務・個情", "広報", "経営"], raci, [32, 14, 14, 18, 14, 14]),
        "xl/worksheets/sheet3.xml": simpleSheet("案件の前提・未確認事項", ["区分", "内容", "補足・根拠"], inputs, [24, 52, 70]),
        "docProps/core.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>${esc(current.d.caseName)} 対応計画</dc:title><dc:creator>Incident Disclosure Navigator</dc:creator><dcterms:created xsi:type="dcterms:W3CDTF">${new Date().toISOString()}</dcterms:created></cp:coreProperties>`,
        "docProps/app.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>Incident Disclosure Navigator</Application></Properties>`
    };
}
const crcTable = ( () => {
    const t = [];
    for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++)
            c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
        t[n] = c >>> 0
    }
    return t
}
)();
function crc32(a) {
    let c = 0xffffffff;
    for (const b of a)
        c = crcTable[(c ^ b) & 255] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0
}
function le16(n) {
    return [n & 255, n >>> 8 & 255]
}
function le32(n) {
    return [n & 255, n >>> 8 & 255, n >>> 16 & 255, n >>> 24 & 255]
}
function makeZip(files) {
    const enc = new TextEncoder()
      , local = []
      , central = [];
    let offset = 0;
    const now = new Date()
      , dosTime = (now.getHours() << 11) | (now.getMinutes() << 5) | (now.getSeconds() >> 1)
      , dosDate = ((now.getFullYear() - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate();
    for (const [name,text] of Object.entries(files)) {
        const nb = enc.encode(name)
          , data = enc.encode(text)
          , crc = crc32(data)
          , lh = new Uint8Array([...le32(0x04034b50), ...le16(20), 0, 0, 0, 0, ...le16(dosTime), ...le16(dosDate), ...le32(crc), ...le32(data.length), ...le32(data.length), ...le16(nb.length), 0, 0, ...nb, ...data]);
        local.push(lh);
        const ch = new Uint8Array([...le32(0x02014b50), ...le16(20), ...le16(20), 0, 0, 0, 0, ...le16(dosTime), ...le16(dosDate), ...le32(crc), ...le32(data.length), ...le32(data.length), ...le16(nb.length), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ...le32(offset), ...nb]);
        central.push(ch);
        offset += lh.length
    }
    const csize = central.reduce( (n, a) => n + a.length, 0)
      , end = new Uint8Array([...le32(0x06054b50), 0, 0, 0, 0, ...le16(central.length), ...le16(central.length), ...le32(csize), ...le32(offset), 0, 0])
      , all = [...local, ...central, end]
      , out = new Uint8Array(all.reduce( (n, a) => n + a.length, 0));
    let p = 0;
    all.forEach(a => {
        out.set(a, p);
        p += a.length
    }
    );
    return out
}
function exportXlsx() {
    const bytes = makeZip(workbookParts())
      , blob = new Blob([bytes],{
        type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    })
      , a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${(current.d.caseName || "インシデント").replace(/[\\/:*?"<>|]/g, "_")}_対応計画.xlsx`;
    a.click();
    setTimeout( () => URL.revokeObjectURL(a.href), 1000)
}
function refresh(reason="入力を更新") {
    render(analyze(readForm()));
    audit.unshift({
        time: new Date().toISOString(),
        event: reason
    })
}
function applyPreset(name) {
    answers = {
        exfil: "unknown",
        containment: "unknown",
        dataScope: "unknown",
        contract: "unknown"
    };
    fill(presets[name]);
    document.querySelectorAll("[data-preset]").forEach(b => b.classList.toggle("selected", b.dataset.preset === name));
    refresh(`${name}シナリオを読込`)
}
function saveCase() {
    const cases = JSON.parse(localStorage.getItem("idn_cases") || "[]")
      , record = {
        id: current.d.caseName,
        updated: new Date().toISOString(),
        data: current.d,
        answers,
        audit
    };
    const i = cases.findIndex(x => x.id === record.id);
    i >= 0 ? cases[i] = record : cases.unshift(record);
    localStorage.setItem("idn_cases", JSON.stringify(cases.slice(0, 10)));
    $("saveState").textContent = `保存済み ${new Date().toLocaleTimeString("ja-JP", {
        hour: "2-digit",
        minute: "2-digit"
    })}`;
    showHistory()
}
function showHistory() {
    const cases = JSON.parse(localStorage.getItem("idn_cases") || "[]");
    $("savedCases").innerHTML = cases.length ? cases.map( (c, i) => `<button class="saved-case" data-load="${i}"><strong>${esc(c.id)}</strong><span>${new Date(c.updated).toLocaleString("ja-JP")}</span></button>`).join("") : '<p class="empty">保存された案件はありません。</p>';
    $("auditLog").innerHTML = audit.length ? audit.slice(0, 12).map(a => `<div><time>${new Date(a.time).toLocaleString("ja-JP")}</time><span>${esc(a.event)}</span></div>`).join("") : '<p class="empty">変更履歴はまだありません。</p>';
    $("historyDialog").showModal()
}
function download() {
    const blob = new Blob([JSON.stringify({
        exportedAt: new Date().toISOString(),
        assessment: current,
        answers,
        audit
    }, null, 2)],{
        type: "application/json"
    })
      , a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${current.d.caseName || "incident"}.json`;
    a.click();
    URL.revokeObjectURL(a.href)
}

$("incidentForm").addEventListener("submit", e => {
    e.preventDefault();
    refresh("判定を更新")
}
);
document.querySelectorAll("[data-preset]").forEach(b => b.addEventListener("click", () => applyPreset(b.dataset.preset)));
document.querySelectorAll("[data-tab]").forEach(b => b.addEventListener("click", () => {
    document.querySelectorAll("[data-tab]").forEach(x => x.classList.toggle("active", x === b));
    document.querySelectorAll(".tab-panel").forEach(x => x.classList.toggle("active", x.id === b.dataset.tab))
}
));
$("questionCards").addEventListener("click", e => {
    const b = e.target.closest("[data-value]");
    if (!b)
        return;
    answers[b.parentElement.dataset.answer] = b.dataset.value;
    refresh("追加質問を更新")
}
);
$("planRows").addEventListener("change", () => {
    collectPlan();
    $("saveState").textContent = "計画を編集済み"
}
);
$("xlsxBtn").addEventListener("click", exportXlsx);
document.querySelectorAll("[data-progress]").forEach(b => b.addEventListener("click", () => {
    const p = b.dataset.progress;
    if (p === "detect") {
        fill({
            leakStatus: "suspected",
            affectedCount: 0,
            countConfidence: "unknown"
        });
        answers.exfil = "unknown"
    }
    if (p === "exfil") {
        fill({
            leakStatus: "confirmed",
            affectedCount: 4200,
            countConfidence: "max"
        });
        answers.exfil = "yes"
    }
    if (p === "final") {
        fill({
            leakStatus: "confirmed",
            affectedCount: 3862,
            countConfidence: "confirmed"
        });
        answers.exfil = "yes";
        answers.dataScope = "yes";
        answers.containment = "yes"
    }
    refresh(`調査進展「${b.textContent}」を反映`)
}
));
$("draftTarget").addEventListener("change", renderDraft);
$("aiDraftBtn").addEventListener("click", generateAiDraft);
$("saveBtn").addEventListener("click", saveCase);
$("historyBtn").addEventListener("click", showHistory);
$("closeHistory").addEventListener("click", () => $("historyDialog").close());
$("savedCases").addEventListener("click", e => {
    const b = e.target.closest("[data-load]");
    if (!b)
        return;
    const c = JSON.parse(localStorage.getItem("idn_cases") || "[]")[Number(b.dataset.load)];
    fill(c.data);
    answers = c.answers;
    audit = c.audit || [];
    $("historyDialog").close();
    refresh("保存案件を再読込")
}
);
$("copyBtn").addEventListener("click", async () => {
    try {
        await navigator.clipboard.writeText($("draftText").value)
    } catch {
        $("draftText").select();
        document.execCommand("copy")
    }
    $("copyToast").classList.add("show");
    setTimeout( () => $("copyToast").classList.remove("show"), 1200)
}
);
$("draftText").addEventListener("input", syncPrintDraft);
$("printBtn").addEventListener("click", () => {
    syncPrintDraft();
    window.print()
}
);
$("exportBtn").addEventListener("click", download);
$("newCaseBtn").addEventListener("click", () => {
    applyPreset("blank");
    audit = [];
    refresh("空白の新規案件を作成")
}
);
if (document.modelContext?.registerTool)
    document.modelContext.registerTool({
        name: "assess_incident",
        title: "インシデント一次判定",
        description: "空白案件または検証済みテンプレートから一次判定を開始します。",
        inputSchema: {
            type: "object",
            properties: {
                preset: {
                    type: "string",
                    enum: ["blank", "mistake", "ecommerce", "hospital"]
                }
            },
            required: ["preset"],
            additionalProperties: false
        },
        annotations: {
            readOnlyHint: false,
            untrustedContentHint: false
        },
        execute({preset}) {
            applyPreset(preset);
            return {
                decision: current.decision,
                severity: current.severity,
                reasons: current.reasons
            }
        }
    });
setDefaultDate();
applyPreset("blank");
