import lief
import capstone
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk
import sys

class REAssistant:
    def __init__(self):
        self.file_path = None
        self.binary = None

    def load_binary(self, progress_var):
        if self.file_path:
            try:
                self.binary = lief.parse(self.file_path)
                progress_var.set(50)  # Progresso al 50% dopo il caricamento del file
            except lief.exception as e:
                print(f"Errore durante il caricamento del file: {e}")
                sys.exit(1)
    
    def get_functions_list(self):
        if self.binary is None:
            return "Carica prima il file eseguibile."

        functions_list = ""
        architecture = self.binary.header.machine_type

        for func in self.binary.exported_functions:
            functions_list += f"{func.name}\n"

        return functions_list

    def disassemble_selected_function(self, function_name):
        if self.binary is None:
            return "Carica prima il file eseguibile."

        selected_function = self.binary.get_exported_function(function_name)
        if selected_function is not None:
            function_address = selected_function.virtual_address
            return self.disassemble_function(function_address)

        return f"Funzione '{function_name}' non trovata."
    
    def search_instructions(self, function_address, target_instruction):
        if self.binary is None:
            return "Carica prima il file eseguibile."

        search_result = ""
        architecture = self.binary.header.machine_type
        code_section = None

        # Trova la sezione contenente il codice
        for section in self.binary.sections:
            if section.content_type == lief.PE.SECTION_CONTENT_TYPES.CODE:
                code_section = section
                break

        if code_section is not None:
            # Ottieni il contenuto della sezione del codice
            code_content = code_section.content

            # Configura il disassemblatore Capstone
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32 if architecture == lief.PE.MACHINE_TYPES.I386 else capstone.CS_MODE_64)
            cs.syntax = capstone.CS_OPT_SYNTAX_INTEL

            # Cerca le istruzioni nel codice della funzione
            for i in cs.disasm(code_content, function_address):
                if target_instruction.lower() in i.mnemonic.lower() or target_instruction.lower() in i.op_str.lower():
                    search_result += f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}\n"

        return search_result

    def disassemble_function(self, function_address):
        if self.binary is None:
            return "Carica prima il file eseguibile."

        disasm_result = ""
        architecture = self.binary.header.machine_type
        code_section = None

        # Trova la sezione contenente il codice
        for section in self.binary.sections:
            if section.content_type == lief.PE.SECTION_CONTENT_TYPES.CODE:
                code_section = section
                break

        if code_section is not None:
            # Ottieni il contenuto della sezione del codice
            code_content = code_section.content

            # Configura il disassemblatore Capstone
            cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32 if architecture == lief.PE.MACHINE_TYPES.I386 else capstone.CS_MODE_64)
            cs.syntax = capstone.CS_OPT_SYNTAX_INTEL

            # Disassembla le istruzioni nella funzione specificata
            for i in cs.disasm(code_content, function_address):
                disasm_result += "0x%x:\t%s\t%s\n" % (i.address, i.mnemonic, i.op_str)

        return disasm_result

    def get_basic_info(self):
        if self.binary is None:
            return "Carica prima il file eseguibile."

        if isinstance(self.binary, lief.PE.Binary):
            info_text = (
                f"Informazioni di base per il file: {self.file_path}\n"
                f"Formato: PE (Portable Executable)\n"
                f"Entrypoint: {hex(self.binary.entrypoint)}\n"
                f"Numero di sezioni: {len(self.binary.sections)}"
            )
        else:
            info_text = (
                f"Informazioni di base per il file: {self.file_path}\n"
                f"Formato: Sconosciuto"
            )
        return info_text

    def get_sections_info(self):
        if self.binary is None:
            return "Carica prima il file eseguibile."

        sections_info = "Informazioni sulle sezioni:\n"
        for section in self.binary.sections:
            sections_info += f"Nome: {section.name}, "
            sections_info += f"Indirizzo: {hex(section.virtual_address)}, "
            sections_info += f"Dimensione: {hex(section.size)}\n"

        return sections_info

    def get_strings(self):
        if self.binary is None:
            return "Carica prima il file eseguibile."

        strings_info = "Stringhe presenti nel file:\n"
        for section in self.binary.sections:
            strings = self.find_strings(section.content)
            for string in strings:
                strings_info += f"{hex(section.virtual_address)}: {string}\n"

        return strings_info

    def find_strings(self, content):
        strings = []
        current_string = ""

        for byte in content:
            if byte >= 32 and byte <= 126:  # ASCII printable characters
                current_string += chr(byte)
            elif current_string:
                strings.append(current_string)
                current_string = ""

        if current_string:
            strings.append(current_string)

        return strings

    def get_symbols_info(self):
        if self.binary is None:
            return "Carica prima il file eseguibile."

        symbols_info = "Informazioni sui simboli presenti nel file:\n"
        for symbol in self.binary.symbols:
            symbols_info += f"Nome: {symbol.name}, "
            symbols_info += f"Indirizzo: {hex(symbol.value)}\n"

        return symbols_info

    def export_to_file(self, output_file):
        basic_info = self.get_basic_info()
        sections_info = self.get_sections_info()
        strings_info = self.get_strings()
        symbols_info = self.get_symbols_info()

        with open(output_file, 'w') as file:
            file.write(f"{basic_info}\n\n{sections_info}\n\n{strings_info}\n\n{symbols_info}")
class REAssistantGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("REAssistant - Reverse Engineering AI")

        self.re_assistant = REAssistant()

        self.create_widgets()

    def create_widgets(self):
        self.label = tk.Label(self.root, text="Seleziona un file eseguibile:")
        self.label.pack(pady=10)

        self.browse_button = tk.Button(self.root, text="Sfoglia", command=self.browse_file)
        self.browse_button.pack(pady=10)

        self.analyze_button = tk.Button(self.root, text="Analizza", command=self.analyze_file)
        self.analyze_button.pack(pady=10)

        self.export_button = tk.Button(self.root, text="Esporta su file", command=self.export_to_file)
        self.export_button.pack(pady=10)

        self.result_text = scrolledtext.ScrolledText(self.root, height=15, width=80)
        self.result_text.pack(pady=10)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.root, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill='x', pady=10)
        self.functions_list_button = tk.Button(self.root, text="Visualizza Lista Funzioni", command=self.show_functions_list)
        self.functions_list_button.pack(pady=10)

        self.selected_function_label = tk.Label(self.root, text="Seleziona una funzione:")
        self.selected_function_label.pack(pady=5)

        self.selected_function_var = tk.StringVar()
        self.functions_combobox = ttk.Combobox(self.root, textvariable=self.selected_function_var)
        self.functions_combobox.pack(pady=10)

        self.disassemble_function_button = tk.Button(self.root, text="Disassembla Funzione", command=self.disassemble_selected_function)
        self.disassemble_function_button.pack(pady=10)

    def show_functions_list(self):
        functions_list = self.re_assistant.get_functions_list()
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, functions_list)

        # Popola la Combobox con la lista di funzioni
        functions = [func.name for func in self.re_assistant.binary.exported_functions]
        self.functions_combobox['values'] = functions

    def disassemble_selected_function(self):
        selected_function = self.selected_function_var.get()
        if selected_function:
            disasm_result = self.re_assistant.disassemble_selected_function(selected_function)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, disasm_result)
        else:
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "Seleziona una funzione dalla lista.")
            
    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("File eseguibile", "*.exe")])
        if file_path:
            self.re_assistant.file_path = file_path
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"File selezionato: {file_path}")

    def analyze_file(self):
        self.progress_var.set(0)
        self.root.update_idletasks()

        self.re_assistant.load_binary(self.progress_var)

        basic_info = self.re_assistant.get_basic_info()
        sections_info = self.re_assistant.get_sections_info()
        strings_info = self.re_assistant.get_strings()
        symbols_info = self.re_assistant.get_symbols_info()

        # Aggiungi il disassemblaggio di una funzione (esempio: entrypoint)
        entrypoint_disasm = self.re_assistant.disassemble_function(self.re_assistant.binary.entrypoint)

        # Aggiungi la ricerca di istruzioni specifiche nell'entrypoint (esempio: 'mov' come target_instruction)
        search_result = self.re_assistant.search_instructions(self.re_assistant.binary.entrypoint, 'mov')

        result = f"{basic_info}\n\n{sections_info}\n\n{strings_info}\n\n{symbols_info}\n\nDisassembly dell'entrypoint:\n{entrypoint_disasm}\n\nRicerca di istruzioni 'mov' nell'entrypoint:\n{search_result}"
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, result)

    def export_to_file(self):
        output_file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("File di testo", "*.txt")])
        if output_file:
            self.re_assistant.export_to_file(output_file)
            self.result_text.insert(tk.END, f"\n\nDati esportati su: {output_file}")

if __name__ == "__main__":
    root = tk.Tk()
    app = REAssistantGUI(root)
    root.mainloop()