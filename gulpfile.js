let {clean, restore, build, test, pack, push} = require('gulp-dotnet-cli');
let gulp = require('gulp');
let argv = require('yargs').argv;
let settings = {
    projectname: 'CryptSharpStandard.SCryptSubset',
    config: argv.config || 'Release',
    version: argv.version || 'Undefined'
}
//clean
gulp.task('clean', ()=>{
    return gulp.src('**/*.csproj', {read: false})
        .pipe(clean({configuration: settings.config}));
});
//restore nuget packages
gulp.task('restore', ()=>{
    return gulp.src('**/*.sln', {read: false})
        .pipe(restore());
});
//compile
gulp.task('build', ()=>{
    return gulp.src('**/*.sln', {read: false})
        .pipe(build({
            configuration: settings.config, 
            version: settings.version 
        }));
});
//run unit tests
gulp.task('test', ()=>{
    return gulp.src('**/*UnitTests.csproj', {read: false})
        .pipe(test());
});
//create nuget package
gulp.task('pack', ()=>{
    return gulp.src('src/' + settings.projectname + '/*.csproj', {read: false})
        .pipe(pack({
            configuration: settings.config,
            output: '../../nupkgs',
            version: settings.version
        }));
});
//push nuget package to local folder
gulp.task('pushlocal', ()=>{
    return gulp.src('nupkgs/*.nupkg', {read: false})
        .pipe(push({source: 'c:/localnuget', echo: true}));
});