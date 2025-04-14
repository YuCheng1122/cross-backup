//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

public class ExtractPcodeAndFunctionCalls extends GhidraScript {

    private Logger extractionLogger;
    private Logger timingLogger;
    private static final String STORAGE_BASE_DIR = "/home/tommy/datasets/cross-architecture";

    /**
     * Configure logging settings
     * 
     * @param outputDir Output directory path
     * @return void
     */
    private void configureLogging(String outputDir) throws IOException {
        // Create log directory in the new storage location
        File logDir = new File(STORAGE_BASE_DIR, "logs");
        if (!logDir.exists()) {
            logDir.mkdirs();
        }
        
        // Extract filename
        String progFileName = getProgramFile().getName();
        
        // Setup extraction logger
        String extractionLogFile = new File(logDir, progFileName + "_extraction.log").getAbsolutePath();
        println("Logs recorded at: " + extractionLogFile);
        
        extractionLogger = Logger.getLogger("extraction_logger_" + progFileName);
        extractionLogger.setLevel(Level.INFO);
        
        FileHandler extractionHandler = new FileHandler(extractionLogFile);
        extractionHandler.setFormatter(new Formatter() {
            @Override
            public String format(LogRecord record) {
                SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                String timestamp = dateFormat.format(new Date(record.getMillis()));
                return timestamp + " - " + record.getLevel() + " - " + record.getMessage() + "\n";
            }
        });
        extractionLogger.addHandler(extractionHandler);
        
        // Setup timing logger
        String timingLogFile = new File(logDir, progFileName + "_timing.log").getAbsolutePath();
        println("Timing logs recorded at: " + timingLogFile);
        
        timingLogger = Logger.getLogger("timing_logger_" + progFileName);
        timingLogger.setLevel(Level.INFO);
        
        FileHandler timingHandler = new FileHandler(timingLogFile);
        timingHandler.setFormatter(new Formatter() {
            @Override
            public String format(LogRecord record) {
                SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                String timestamp = dateFormat.format(new Date(record.getMillis()));
                return timestamp + "," + record.getMessage() + "\n";
            }
        });
        timingLogger.addHandler(timingHandler);
    }

    private HighFunction getHighFunction(Function func, DecompInterface ifc, TaskMonitor monitor) throws Exception {
        DecompileResults res = ifc.decompileFunction(func, 60, monitor);
        return res.getHighFunction();
    }

    private List<String> createPcodeList(HighFunction highFunc) {
        List<String> pcodeList = new ArrayList<>();
        Iterator<PcodeOpAST> opiter = highFunc.getPcodeOps();
        while (opiter.hasNext()) {
            PcodeOpAST op = opiter.next();
            pcodeList.add(op.toString());
        }
        return pcodeList;
    }

    private boolean isExternalFunction(Function func) {
        println("Function: " + func.getName() + 
                ", isExternal: " + func.isExternal() + 
                ", isThunk: " + func.isThunk() + 
                ", isLibrary: " + func.isLibrary());
        
        return func.isExternal() || func.isThunk() || func.isLibrary();
    }

    private Map<String, List<String>> extractPcode(Program program, DecompInterface ifc, TaskMonitor monitor)
            throws Exception {
        timingLogger.info("Started extracting P-Code");
        long startTime = System.currentTimeMillis();

        Map<String, List<String>> pcodeMap = new HashMap<>();
        FunctionManager funcManager = program.getFunctionManager();
        // Get memory object to check executable sections
        Memory memory = program.getMemory();

        // Use iterator to traverse all functions
        Iterator<Function> funcs = funcManager.getFunctions(true).iterator();
        int count = 0;
        int skippedNonExecutable = 0;
        int skippedExternal = 0;

        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function func = funcs.next();
            Address entryPoint = func.getEntryPoint();
            String addrStr = "0x" + entryPoint.toString();
            
            // Check if function is external/imported
            if (isExternalFunction(func)) {
                extractionLogger.fine("Skipping external function: " + func.getName() + " at " + addrStr);
                skippedExternal++;
                continue;
            }
            
            // Check if function is in executable memory
            MemoryBlock block = memory.getBlock(entryPoint);
            if (block == null || !block.isExecute()) {
                extractionLogger.fine("Skipping function at " + addrStr + " - not in executable memory");
                skippedNonExecutable++;
                continue;
            }
            
            try {
                HighFunction highFunc = getHighFunction(func, ifc, monitor);
                if (highFunc != null) {
                    List<String> pcodeList = createPcodeList(highFunc);
                    pcodeMap.put(addrStr, pcodeList);
                    count++;
                    
                    if (count % 100 == 0) {
                        extractionLogger.info("Processed " + count + " functions");
                    }
                }
            } catch (Exception e) {
                extractionLogger.warning("Error while processing function " + addrStr + ": " + e.getMessage());
            }
        }

        long endTime = System.currentTimeMillis();
        timingLogger.info("P-Code extraction completed,duration," + (endTime - startTime) + 
                        "ms,functions processed," + count + 
                        ",skipped non-executable," + skippedNonExecutable +
                        ",skipped external," + skippedExternal);
        extractionLogger.info("Total processed functions: " + count + 
                            ", Skipped non-executable: " + skippedNonExecutable +
                            ", Skipped external: " + skippedExternal);

        return pcodeMap;
    }

    private Map<String, List<String>> extractFunctionCalls(Program program, TaskMonitor monitor) throws Exception {
        timingLogger.info("Started extracting function call relationships");
        long startTime = System.currentTimeMillis();
        
        Map<String, List<String>> functionCalls = new HashMap<>();
        FunctionManager funcManager = program.getFunctionManager();
        // Get memory object to check executable sections
        Memory memory = program.getMemory();
        
        Iterator<Function> funcs = funcManager.getFunctions(true).iterator();
        int count = 0;
        int skippedNonExecutable = 0;
        int skippedExternal = 0;
        
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function func = funcs.next();
            Address entryPoint = func.getEntryPoint();
            String addrStr = "0x" + entryPoint.toString();
            
            // Check if function is external/imported
            if (isExternalFunction(func)) {
                skippedExternal++;
                continue;
            }
            
            // Check if function is in executable memory
            MemoryBlock block = memory.getBlock(entryPoint);
            if (block == null || !block.isExecute()) {
                skippedNonExecutable++;
                continue;
            }
            
            try {
                // Get called functions
                Set<Function> calledFuncs = func.getCalledFunctions(monitor);
                List<String> calledList = new ArrayList<>();
                for (Function f : calledFuncs) {
                    // You may also want to filter called functions to only include non-external executable ones
                    // However, we'll keep external functions in the called list as it's useful to know what external functions are called
                    // But we will still filter for executable memory
                    Address calledEntryPoint = f.getEntryPoint();
                    MemoryBlock calledBlock = memory.getBlock(calledEntryPoint);
                    if (calledBlock != null && calledBlock.isExecute()) {
                        calledList.add("0x" + calledEntryPoint.toString());
                    }
                }
                
                functionCalls.put(addrStr, calledList);
                count++;
                
                if (count % 100 == 0) {
                    extractionLogger.info("Processed " + count + " function call relationships");
                }
            } catch (Exception e) {
                extractionLogger.warning("Error while processing function call " + addrStr + ": " + e.getMessage());
            }
        }
        
        long endTime = System.currentTimeMillis();
        timingLogger.info("Function call extraction completed,duration," + (endTime - startTime) + 
                            "ms,functions processed," + count + 
                            ",skipped non-executable," + skippedNonExecutable +
                            ",skipped external," + skippedExternal);
        extractionLogger.info("Total processed function call relationships: " + count + 
                                ", Skipped non-executable: " + skippedNonExecutable +
                                ", Skipped external: " + skippedExternal);
        
        return functionCalls;
    }

    /**
     * Calculate MD5 hash for FCG (Function Call Graph)
     * @param functionCalls Map of function calls
     * @return String MD5 hash of the FCG
     */
    private String calculateFCGHash(Map<String, List<String>> functionCalls) throws NoSuchAlgorithmException {
        timingLogger.info("Started calculating FCG hash");
        long startTime = System.currentTimeMillis();
        
        // Sort the function addresses to ensure consistent hashing
        List<String> sortedFunctions = new ArrayList<>(functionCalls.keySet());
        Collections.sort(sortedFunctions);
        
        StringBuilder sb = new StringBuilder();
        
        // Build a string representation of the FCG
        for (String funcAddr : sortedFunctions) {
            sb.append(funcAddr).append(":");
            
            List<String> calledFuncs = functionCalls.get(funcAddr);
            if (calledFuncs != null && !calledFuncs.isEmpty()) {
                // Sort called functions for consistency
                Collections.sort(calledFuncs);
                
                for (String calledFunc : calledFuncs) {
                    sb.append(calledFunc).append(",");
                }
                // Remove the last comma
                if (!calledFuncs.isEmpty()) {
                    sb.setLength(sb.length() - 1);
                }
            }
            sb.append(";");
        }
        
        // Calculate MD5 hash
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(sb.toString().getBytes());
        
        // Convert to hex string
        StringBuilder hexString = new StringBuilder();
        for (byte b : digest) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        
        long endTime = System.currentTimeMillis();
        timingLogger.info("FCG hash calculation completed,duration," + (endTime - startTime) + "ms");
        extractionLogger.info("FCG hash calculated: " + hexString.toString());
        
        return hexString.toString();
    }

    @Override
    public void run() throws Exception {
        // Record start time
        Date startTime = new Date();
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        
        Program program = currentProgram;
        
        // Set output to new storage location
        String outputDirectory = new File(STORAGE_BASE_DIR, "results").getAbsolutePath();
        
        // Get filename and architecture information
        String progFileName = getProgramFile().getName();
        String arch = program.getLanguage().getProcessor().toString();
        
        // Create output directory matching the data directory structure
        File binaryFile = getProgramFile();
        String relativePath = getRelativePathFromData(binaryFile.getAbsolutePath());
        if (relativePath != null) {
            // Get the directory part by removing the actual filename
            String fileName = binaryFile.getName();
            String dirPath = relativePath;
            
            // If relativePath ends with the fileName, remove it to get just the directory
            if (dirPath.endsWith("/" + fileName)) {
                dirPath = dirPath.substring(0, dirPath.length() - fileName.length() - 1);
            }
            
            // Create the directory structure
            File resultDir = new File(outputDirectory, dirPath);
            if (!resultDir.exists()) {
                resultDir.mkdirs();
            }
            
            // Set the output directory to the created directory
            outputDirectory = resultDir.getAbsolutePath();
        }
        
        // Log the output directory path
        println("Results will be saved to: " + outputDirectory);
        
        // Configure logging
        configureLogging(outputDirectory);
        
        // Output log information
        extractionLogger.info("Started analyzing file: " + progFileName);
        extractionLogger.info("Architecture: " + arch);
        extractionLogger.info("Start time: " + dateFormat.format(startTime));
        
        // Initialize decompilation interface
        DecompInterface ifc = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        ifc.setOptions(options);
        ifc.openProgram(program);
        
        // Extract P-Code and function calls
        Map<String, List<String>> pcodeMap = extractPcode(program, ifc, monitor);
        Map<String, List<String>> functionCalls = extractFunctionCalls(program, monitor);
        
        // Calculate FCG hash
        String fcgHash = calculateFCGHash(functionCalls);
        
        // Organize output data
        Map<String, Object> result = new HashMap<>();
        result.put("pcode", pcodeMap);
        result.put("function_calls", functionCalls);
        result.put("fcg_hash", fcgHash);
        
        // Add log information
        Map<String, String> logInfo = new HashMap<>();
        logInfo.put("file_name", progFileName);
        logInfo.put("architecture", arch);
        logInfo.put("start_time", dateFormat.format(startTime));
        logInfo.put("end_time", dateFormat.format(new Date()));
        result.put("log_info", logInfo);
        
        // Output file
        String outputFileName = progFileName + ".json";
        File outputFile = new File(outputDirectory, outputFileName);
        
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String jsonString = gson.toJson(result);
        
        FileWriter writer = new FileWriter(outputFile);
        writer.write(jsonString);
        writer.close();
        
        // Output end log
        Date endTime = new Date();
        long duration = endTime.getTime() - startTime.getTime();
        
        extractionLogger.info("Analysis completed!");
        extractionLogger.info("End time: " + dateFormat.format(endTime));
        extractionLogger.info("Total duration: " + duration + " milliseconds");
        extractionLogger.info("FCG Hash: " + fcgHash);
        extractionLogger.info("Output saved to: " + outputFile.getAbsolutePath());
        
        println("Analysis completed!");
        println("End time: " + dateFormat.format(endTime));
        println("FCG Hash: " + fcgHash);
        println("Output saved to: " + outputFile.getAbsolutePath());
    }
    
    /**
     * Get relative path from the data directory from the absolute path
     * 
     * @param absolutePath File absolute path
     * @return String Relative path or null (if not under the data directory)
     */
    private String getRelativePathFromData(String absolutePath) {
        String[] pathParts = absolutePath.split("/");
        for (int i = 0; i < pathParts.length; i++) {
            if (pathParts[i].startsWith("data_") && i + 1 < pathParts.length) {
                StringBuilder relativePath = new StringBuilder();
                for (int j = i + 1; j < pathParts.length; j++) {
                    relativePath.append(pathParts[j]);
                    if (j < pathParts.length - 1) {
                        relativePath.append("/");
                    }
                }
                return relativePath.toString();
            }
        }
        // If we can't find a data_ directory, try to preserve at least some folder structure
        // by using the last few directories
        String[] parts = absolutePath.split("/");
        if (parts.length > 3) {
            // Use last 2 directory levels
            return parts[parts.length-3] + "/" + parts[parts.length-2];
        }
        return null;
    }
}