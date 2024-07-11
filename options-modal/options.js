class UserConfig {
  constructor() {
    this.defaultConfig = {
      refreshInterval: 1,
      useIcons: false,
      useGradients: false,
      strikethroughCompleted: true,
      completedOpacity: 0.14,
    };
    this.defaultColormap = {
      Urgent: {
        color: "#EE4B2B",
        secondaryColor: "#FFA500",
        icon: "🔥",
        blinkWhenClose: true,
      },
      Critical: {
        color: "#FFA500",
        secondaryColor: "#FFA500",
        icon: "🚨",
        blinkWhenClose: true,
      },
      Daily: {
        color: "#BEBDBF",
        secondaryColor: "#BEBDBF",
        icon: "📅",
        blinkWhenClose: false,
      },
      Fitness: {
        color: "#546E7A",
        secondaryColor: "#546E7A",
        icon: "🏋️",
        blinkWhenClose: false,
      },
      Pets: {
        color: "#546E7A",
        secondaryColor: "#546E7A",
        icon: "🐶",
        blinkWhenClose: false,
      },
      Housework: {
        color: "#546E7A",
        secondaryColor: "#546E7A",
        icon: "🧹",
        blinkWhenClose: false,
      },
      Maintenance: {
        color: "#546E7A",
        secondaryColor: "#546E7A",
        icon: "🔧",
        blinkWhenClose: false,
      },
      "Side Hustle": {
        color: "#546E7A",
        secondaryColor: "#546E7A",
        icon: "💼",
        blinkWhenClose: false,
      },
      Kids: {
        color: "#607D8B",
        secondaryColor: "#607D8B",
        icon: "👶",
        blinkWhenClose: false,
      },
      Work: {
        color: "#F24162",
        secondaryColor: "#F24162",
        icon: "💼",
        blinkWhenClose: false,
      },
      Appointments: {
        color: "#1BBC9B",
        secondaryColor: "#1BBC9B",
        icon: "📅",
        blinkWhenClose: false,
      },
    };
    this.deleteBackups = [];
    this.idMap = {};

    this.updateLegacyOptionsSave();
    this.loadOptions();

    document
      .querySelector("#restoreDeletedButton")
      .addEventListener("click", () => {
        this.restoreDeletedRow();
      });
    document.querySelector("#saveButton").addEventListener("click", () => {
      this.mutateUpdateSettings();
    });
    document
      .querySelector("#saveButtonConfig")
      .addEventListener("click", () => {
        this.mutateUpdateConfig();
      });
  }

  reRenderTable() {
    document.querySelector("#configTableBody").innerHTML = "";
    document.querySelector("#configTableHeaderRow").innerHTML = "";
    this.loadOptions();
  }

  async mutateUpdateSettings() {
    const tableBody = document.querySelector("#configTableBody");
    const rows = tableBody.querySelectorAll("tr");
    for (let [tag, tagConfig] of Object.entries(this.options.colormap)) {
      this.mutateDelRow([tag, ...Object.values(tagConfig)], false);
    }
    for (let row of rows) {
      if (row.id == "addRow") {
        continue;
      }
      const rowData = [];
      for (let cell of row.children) {
        const input = cell.querySelector("input");
        if (input) {
          rowData.push(input.value);
        }
      }
      this.mutateAddRow(rowData);
    }
  }

  async mutateUpdateConfig() {
    const config = this.getConfigFromUI();
    for (let [key, value] of Object.entries(config)) {
      this.options[key] = value;
    }
    chrome.storage.sync.set({
      taskColorConfig: JSON.stringify(this.options),
    });
  }

  getConfigFromUI() {
    const config = structuredClone(this.defaultConfig);
    for (let key of Object.keys(config)) {
      if (typeof this.defaultConfig[key] === "boolean") {
        config[key] = document.querySelector(`#${key}`).checked;
      } else if (typeof this.defaultConfig[key] === "number") {
        config[key] = parseFloat(document.querySelector(`#${key}`).value);
      } else {
        config[key] = document.querySelector(`#${key}`).value;
      }
    }
    return config;
  }

  async mutateAddRow(rowData) {
    const [tag, ...rest] = rowData;
    const colorMap = {};
    for (let i = 0; i < rest.length; i++) {
      colorMap[this.colNames[i + 1]] = rest[i];
    }
    this.options.colormap[tag] = colorMap;
    await chrome.storage.sync.set({
      taskColorConfig: JSON.stringify(this.options),
    });
  }

  async mutateDelRow(tag, addToUndoStack = true) {
    const target = this.options.colormap[tag];
    if (target && addToUndoStack) {
      this.deleteBackups.push({ tag, target });
    }
    delete this.options.colormap[tag];
    await chrome.storage.sync.set({
      taskColorConfig: JSON.stringify(this.options),
    });
    if (addToUndoStack) {
      const btnTxt = document.querySelector("#restoreDeletedButton");
      // If (n) already in button text, replace it with (n+1)
      if (btnTxt.textContent.includes("(")) {
        const newCount = parseInt(btnTxt.textContent.match(/\d+/)[0]) + 1;
        btnTxt.textContent = `Restore Deleted (${newCount})`;
      } else {
        btnTxt.textContent += " (1)";
      }
    }
  }

  async restoreDeletedRow() {
    const lastDeleted = this.deleteBackups.pop();
    if (lastDeleted) {
      this.options.colormap[lastDeleted.tag] = lastDeleted.target;
      await chrome.storage.sync.set({
        taskColorConfig: JSON.stringify(this.options),
      });
      this.addRow(
        [lastDeleted.tag, ...Object.values(lastDeleted.target)],
        lastDeleted.target.color
      );

      const btnTxt = document.querySelector("#restoreDeletedButton");
      // If (n) already in button text, replace it with (n-1)
      if (btnTxt.textContent.includes("(")) {
        const newCount = parseInt(btnTxt.textContent.match(/\d+/)[0]) - 1;
        if (newCount === 0) {
          btnTxt.textContent = "Restore Deleted";
        } else {
          btnTxt.textContent = `Restore Deleted (${newCount})`;
        }
      }
    }
  }

  async loadOptions() {
    const optionsRes = await chrome.storage.sync.get("taskColorConfig");
    if (!optionsRes) {
      this.options = JSON.parse(JSON.stringify(this.defaultConfig));
      this.options["colormap"] = JSON.parse(
        JSON.stringify(this.defaultColormap)
      );
    } else {
      this.options = JSON.parse(optionsRes.taskColorConfig);
    }
    this.optionsFields = Object.keys(this.options);

    // Populate the config table
    for (let key of Object.keys(this.defaultConfig)) {
      const el = document.querySelector(`#${key}`);
      if (typeof this.defaultConfig[key] === "boolean") {
        el.checked = this.options[key];
      } else if (typeof this.defaultConfig[key] === "number") {
        if (
          typeof this.options[key] === "number" &&
          !isNaN(this.options[key])
        ) {
          el.value = this.options[key];
        } else {
          el.value = parseFloat(this.options[key]);
        }
      } else {
        el.value = this.options[key];
      }
    }

    // Get the object in colorMap with the most keys
    const maxColorMap = Object.keys(this.options.colormap).reduce((a, b) =>
      Object.keys(this.options.colormap[a]).length >
      Object.keys(this.options.colormap[b]).length
        ? a
        : b
    );
    this.colNames = Object.keys(this.options.colormap[maxColorMap]);
    this.colNames.unshift("Tag");
    let index = 0;
    for (let colName of this.colNames) {
      if (colName === "color") {
        this.colorColIndex = index;
        this.addCol(colName, "10rem");
      } else if (colName === "secondaryColor") {
        this.secondaryColorColIndex = index;
        this.addCol(colName, "10rem");
      } else {
        this.addCol(colName);
      }
      index++;
    }

    // Add the "add row" dummy row for manually adding rows
    this.addRow(this.colNames, "", true);

    // Iterate over colormap and addrows to the ui
    for (let [key, value] of Object.entries(this.options.colormap)) {
      const rowCells = [key];
      this.generateIdHash(key);
      let color = "";
      // Add all the values in value
      for (let [colorOptionField, colorOptionVal] of Object.entries(value)) {
        rowCells.push(colorOptionVal);
        if (colorOptionField === "color") {
          color = colorOptionVal;
        }
      }
      this.addRow(rowCells, color);
    }
  }

  convertLegacyOptions(legacyOptions) {
    const convertedColors = {};
    for (let [key, value] of Object.entries(legacyOptions)) {
      convertedColors[key] = {
        color: value,
        secondaryColor: value,
        icon: "🔥",
        blinkWhenClose: false,
      };
    }
    const convertedOptions = structuredClone(this.defaultConfig);
    convertedOptions.colormap = convertedColors;
    return convertedOptions;
  }

  async migrateSettings(legacyOptions) {
    const convertedOptions = this.convertLegacyOptions(legacyOptions);
    await chrome.storage.sync.set({
      taskColorConfig: JSON.stringify(convertedOptions),
    });
    return convertedOptions;
  }

  configsEqual(config1, config2) {
    for (let key of Object.keys(config1)) {
      if (!config2.hasOwnProperty(key) || config1[key] !== config2[key]) {
        return false;
      }
    }
    return true;
  }

  async updateLegacyOptionsSave() {
    try {
      // Load both legacy options in parallel
      const [legacyOptions, storedLegacyOptions] = await Promise.all([
        this.loadLegacyOptionsFile(),
        this.loadLegacyOptionsStorage(),
      ]);

      // If legacy options file doesn't exist, don't need to handle any migration.
      if (!legacyOptions) {
        return;
      }

      // If legacy options hasn't been modified since last access, don't need to update.
      if (this.configsEqual(legacyOptions, storedLegacyOptions)) {
        return;
      }

      const migrateModal = new bootstrap.Modal(
        document.getElementById("migrateModal"),
        {
          keyboard: false,
          backdrop: "static",
        }
      );
      const modalOptionsEl = document.querySelector("#jsonLegacyOptions");
      modalOptionsEl.innerHTML = JSON.stringify(legacyOptions, null, 2);
      migrateModal.show();

      document
        .querySelector("#closeModalButton")
        .addEventListener("click", () => {
          migrateModal.hide();
        });

      document
        .querySelector("#migrateButton")
        .addEventListener("click", async () => {
          await this.migrateSettings(legacyOptions);
          migrateModal.hide();
          this.reRenderTable();
        });

      // Save the latest legacy options to storage
      await chrome.storage.sync.set({ legacy_taskColorConfig: legacyOptions });
    } catch (error) {
      console.error("Error updating legacy options:", error);
    }
  }

  async loadLegacyOptionsStorage() {
    const result = await chrome.storage.sync.get(["legacy_taskColorConfig"]);
    return result.legacy_taskColorConfig || false;
  }

  async loadLegacyOptionsFile() {
    // The legacy options were stored in ./user-data/color-map.json
    try {
      const response = await fetch(
        chrome.runtime.getURL("user-data/color-map.json")
      );
      return response.json();
    } catch (error) {
      return false;
    }
  }

  getIdFromHash(hash) {
    return this.idMap[hash];
  }

  getHashFromId(id) {
    return Object.keys(this.idMap).find((key) => this.idMap[key] === id);
  }

  deleteRow(rowHash) {
    this.mutateDelRow(this.getIdFromHash(rowHash), true);
    document.querySelector(`tr#${rowHash}`).remove();
  }

  addCol(colName, width = false) {
    const th = document.createElement("th");
    th.textContent = colName;
    if (width) {
      th.style.minWidth = width;
    }
    document.querySelector("tr#configTableHeaderRow").appendChild(th);
  }

  generateIdHash(tagString) {
    let candidate = tagString.replace(/\s/g, "");
    if (this.idMap[candidate]) {
      let count = 1;
      while (this.idMap[candidate + count]) {
        count++;
      }
      candidate += count;
    }
    this.idMap[candidate] = tagString;
  }

  addRow(options, color, inputRow = false) {
    const rowKey = options[0].replace(/\s/g, "");
    const tableBody = document.querySelector("#configTableBody");
    const tr = Object.assign(document.createElement("tr"), {
      id: inputRow ? "addRow" : rowKey,
    });

    for (let [index, value] of Object.entries(options)) {
      const td = document.createElement("td");
      const input = Object.assign(document.createElement("input"), {
        type: "text",
        className: inputRow
          ? "form-control editable"
          : index == "0"
          ? "form-control fw-bold text-center"
          : "form-control",
      });
      if (
        this.colorColIndex !== undefined &&
        (index == this.colorColIndex.toString() ||
          index == this.secondaryColorColIndex.toString())
      ) {
        input.type = "color";
        input.style.paddingBlock = "0px";
      }
      if (inputRow) {
        input.placeholder = `Enter ${value}`;
      } else if (parseInt(index) === this.colNames.indexOf("icon")) {
        input.value = JSON.parse(`"${value}"`);
      } else {
        input.value = value;
      }
      td.appendChild(input);
      tr.appendChild(td);
    }
    if (inputRow) {
      const addIconTd = Object.assign(document.createElement("td"), {
        className: "col-xs-1 text-center",
      });
      const span_ = Object.assign(document.createElement("span"), {
        className: "addBtn",
        innerHTML: `<i class="fa fa-plus"></i>`,
      });
      span_.addEventListener("click", () => this.addRowFromUI());
      addIconTd.appendChild(span_);
      tr.appendChild(addIconTd);
      tableBody.prepend(tr);
    } else {
      const deleteIconTd = Object.assign(document.createElement("td"), {
        className: "col-xs-1 text-center",
      });
      const deleteA = Object.assign(document.createElement("a"), {
        href: "#",
        innerHTML: `<i class="fa fa-trash-o" aria-hidden="true"></i>`,
      });
      deleteA.addEventListener("click", () => this.deleteRow(rowKey));
      deleteIconTd.appendChild(deleteA);
      tr.appendChild(deleteIconTd);
      tableBody.appendChild(tr);
    }
  }

  addRowFromUI() {
    const rowCells = [];
    const tr = document.querySelector("#addRow");
    let color = "";
    for (let [index, cell] of Object.entries(tr.children)) {
      const input = cell.querySelector("input");
      if (!input) {
        continue;
      }
      if (input.value === "Enter blinkWhenClose") {
        rowCells.push(false);
      }
      else {
        rowCells.push(input.value);
      }
      if (index === this.colorColIndex) {
        color = input.value;
      }
    }
    this.addRow(rowCells, color);
    this.mutateAddRow(rowCells);
  }
}

document.addEventListener("DOMContentLoaded", function () {
  new UserConfig();
});
