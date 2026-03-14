const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // We probably do eventually want a module to help people make custom programs for moxi.
    const mod = b.addModule("moxi", .{
        // The root source file is the "entry point" of this module. Users of
        // this module will only be able to access public declarations contained
        // in this file, which means that if you have declarations that you
        // intend to expose to consumers that were defined in other files part
        // of this module, you will have to make sure to re-export them from
        // the root file.
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });

    // Here we define an executable. An executable needs to have a root module
    // which needs to expose a `main` function. While we could add a main function
    // to the module defined above, it's sometimes preferable to split business
    // logic and the CLI into two separate modules.
    //
    // If instead your goal is to create an executable, consider if users might
    // be interested in also being able to embed the core functionality of your
    // program in their own executable in order to avoid the overhead involved in
    // subprocessing your CLI tool.
    //
    // If neither case applies to you, feel free to delete the declaration you
    // don't need and to put everything under a single module.
    const exe = b.addExecutable(.{
        .name = "moxi",
        .root_module = b.createModule(.{
            // b.createModule defines a new module just like b.addModule but,
            // unlike b.addModule, it does not expose the module to consumers of
            // this package, which is why in this case we don't have to give it a name.
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "moxi", .module = mod },
            },
        }),
    });

    exe.root_module.link_libc = true;
    exe.root_module.linkSystemLibrary("dw", .{});
    // TODO: Seemingly not actually needed so far.
    exe.root_module.linkSystemLibrary("elf", .{});

    // This declares intent for the executable to be installed into the
    // install prefix when running `zig build` (i.e. when executing the default
    // step). By default the install prefix is `zig-out/` but can be overridden
    // by passing `--prefix` or `-p`.
    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");

    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const mod_tests = b.addTest(.{
        .root_module = mod,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });

    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);

    const zig_helloworld_mod = b.createModule(.{
        .root_source_file = b.path("test/zig_helloworld/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{
                .name = "foo",
                .module = b.addModule("foo", .{
                    .root_source_file = b.path("test/zig_helloworld/root.zig"),
                    .target = target,
                }),
            },
        },
    });

    // Also have the libc module run something from libc.
    const zig_libc_mod = b.createModule(.{
        .root_source_file = b.path("test/zig_helloworld/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{
                .name = "foo",
                .module = b.addModule("foo", .{
                    .root_source_file = b.path("test/zig_helloworld/libc_root.zig"),
                    .target = target,
                }),
            },
        },
        .link_libc = true,
    });

    const zig_helloworld = b.addExecutable(.{
        .name = "zig_helloworld",
        .root_module = zig_helloworld_mod,
    });

    const zig_pie = b.addExecutable(.{
        .name = "zig_pie",
        .root_module = zig_helloworld_mod,
    });
    zig_pie.pie = true;

    const zig_libc = b.addExecutable(.{
        .name = "zig_libc",
        .root_module = zig_libc_mod,
    });

    const testbin_step = b.step("testbinaries", "Build test binaries");
    testbin_step.dependOn(&zig_helloworld.step);
    testbin_step.dependOn(&zig_pie.step);
    testbin_step.dependOn(&zig_libc.step);
    testbin_step.dependOn(&b.addInstallArtifact(zig_helloworld, .{}).step);
    testbin_step.dependOn(&b.addInstallArtifact(zig_pie, .{}).step);
    testbin_step.dependOn(&b.addInstallArtifact(zig_libc, .{}).step);
}
