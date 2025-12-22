const std = @import("std");

fn withTargetSuffix(b: *std.Build, base: []const u8, target_suffix: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, base, '.')) |dot| {
        return b.fmt("{s}-{s}{s}", .{ base[0..dot], target_suffix, base[dot..] });
    }
    return b.fmt("{s}-{s}", .{ base, target_suffix });
}

fn compactTargetSuffix(b: *std.Build, target: std.Build.ResolvedTarget) []const u8 {
    const t = target.result;
    const arch = @tagName(t.cpu.arch);
    const os = @tagName(t.os.tag);
    const abi = @tagName(t.abi);

    if (t.abi == .none) return b.fmt("{s}-{s}", .{ arch, os });
    return b.fmt("{s}-{s}-{s}", .{ arch, os, abi });
}

fn installExeWithSuffix(
    b: *std.Build,
    step: *std.Build.Step,
    exe: *std.Build.Step.Compile,
    target_suffix: []const u8,
) void {
    step.dependOn(&b.addInstallArtifact(exe, .{
        .dest_sub_path = withTargetSuffix(b, exe.out_filename, target_suffix),
        // We'll install a suffixed PDB ourselves (Windows) to match the exe name.
        .pdb_dir = .disabled,
    }).step);

    if (exe.producesPdbFile()) {
        step.dependOn(&b.addInstallFileWithDir(
            exe.getEmittedPdb(),
            .bin,
            withTargetSuffix(b, b.fmt("{s}.pdb", .{exe.name}), target_suffix),
        ).step);
    }
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const target_suffix = compactTargetSuffix(b, target);

    const abi_mod = b.createModule(.{
        .root_source_file = b.path("src/abi.zig"),
        .target = target,
        .optimize = optimize,
    });

    const root_mod = b.createModule(.{
        .root_source_file = b.path("src/libtagalloc.zig"),
        .target = target,
        .optimize = optimize,
    });
    root_mod.addImport("abi", abi_mod);

    const tagalloc_lib = b.addLibrary(.{
        .name = "tagalloc",
        .root_module = root_mod,
        .linkage = .static,
    });

    // Install the header next to the .a for simpler consumption.
    b.getInstallStep().dependOn(&b.addInstallFileWithDir(
        b.path("include/libtagalloc.h"),
        .lib,
        withTargetSuffix(b, "libtagalloc.h", target_suffix),
    ).step);
    b.getInstallStep().dependOn(&b.addInstallArtifact(tagalloc_lib, .{
        .dest_sub_path = withTargetSuffix(b, tagalloc_lib.out_filename, target_suffix),
    }).step);

    const test_step = b.step("test", "Run tests");
    {
        const test_mod = b.createModule(.{
            .root_source_file = b.path("src/tests.zig"),
            .target = target,
            .optimize = optimize,
        });
        test_mod.addImport("abi", abi_mod);

        const poolreader_lib_mod = b.createModule(.{
            .root_source_file = b.path("tools/poolreader/lib.zig"),
            .target = target,
            .optimize = optimize,
        });
        poolreader_lib_mod.addImport("abi", abi_mod);
        test_mod.addImport("poolreader_lib", poolreader_lib_mod);

        const unit_tests = b.addTest(.{ .root_module = test_mod });
        test_step.dependOn(&b.addRunArtifact(unit_tests).step);
    }

    // Poolreader tool.
    const poolreader_step = b.step("poolreader", "Build poolreader");
    {
        const mod = b.createModule(.{
            .root_source_file = b.path("tools/poolreader/main.zig"),
            .target = target,
            .optimize = optimize,
        });
        mod.addImport("abi", abi_mod);
        const exe = b.addExecutable(.{ .name = "poolreader", .root_module = mod });
        installExeWithSuffix(b, poolreader_step, exe, target_suffix);
    }
    b.getInstallStep().dependOn(poolreader_step);

    // Demo programs.
    const demo_step = b.step("demo", "Build demos");
    {
        const demo_zig_mod = b.createModule(.{
            .root_source_file = b.path("examples/demo.zig"),
            .target = target,
            .optimize = optimize,
        });
        demo_zig_mod.addImport("tagalloc", root_mod);
        const demo_zig = b.addExecutable(.{ .name = "demo-zig", .root_module = demo_zig_mod });
        installExeWithSuffix(b, demo_step, demo_zig, target_suffix);

        const quickstart_mod = b.createModule(.{
            .root_source_file = b.path("examples/quickstart.zig"),
            .target = target,
            .optimize = optimize,
        });
        quickstart_mod.addImport("tagalloc", root_mod);
        const quickstart = b.addExecutable(.{ .name = "quickstart", .root_module = quickstart_mod });
        installExeWithSuffix(b, demo_step, quickstart, target_suffix);

        const demo_cpp_mod = b.createModule(.{
            .root_source_file = null,
            .target = target,
            .optimize = optimize,
        });
        const demo_cpp = b.addExecutable(.{ .name = "demo-cpp", .root_module = demo_cpp_mod });
        demo_cpp.addCSourceFile(.{ .file = b.path("examples/demo.cpp"), .flags = &.{"-std=c++17"}, .language = .cpp });
        demo_cpp.linkLibC();
        demo_cpp.linkLibCpp();
        demo_cpp.linkLibrary(tagalloc_lib);
        installExeWithSuffix(b, demo_step, demo_cpp, target_suffix);
    }

    // Benchmarks.
    const bench_step = b.step("benchmark", "Build benchmarks");
    {
        const bench_slab_mod = b.createModule(.{
            .root_source_file = b.path("benchmark/bench_slab.zig"),
            .target = target,
            .optimize = optimize,
        });
        bench_slab_mod.addImport("tagalloc", root_mod);
        const bench_slab = b.addExecutable(.{ .name = "bench-slab", .root_module = bench_slab_mod });
        installExeWithSuffix(b, bench_step, bench_slab, target_suffix);

        const stress_mod = b.createModule(.{
            .root_source_file = b.path("benchmark/stress.zig"),
            .target = target,
            .optimize = optimize,
        });
        stress_mod.addImport("tagalloc", root_mod);
        const stress = b.addExecutable(.{ .name = "stress", .root_module = stress_mod });
        installExeWithSuffix(b, bench_step, stress, target_suffix);
    }
}
